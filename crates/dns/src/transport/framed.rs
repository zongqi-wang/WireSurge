use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};

use super::{Connection, DnsRequest, DnsResponse, TransportCaps, TransportError};
use crate::{MAX_DNS_MESSAGE_LEN, parse_response_header};

/// One outstanding query: the reply slot the reader fills, plus the wakeup the
/// waiter parks on. The `Notify` comes from a per-connection freelist and is
/// reused across queries, so a query costs no heap allocation for correlation
/// (the previous `oneshot` allocated a fresh shared cell every time).
struct Slot {
    notify: Arc<Notify>,
    response: Option<DnsResponse>,
}

struct CorrelatorState {
    pending: HashMap<u16, Slot>,
    /// Recycled `Notify` handles; popped on register, returned on completion or
    /// timeout. Grows only during ramp-up, then steady-state at the in-flight
    /// high-water mark with zero per-query allocation.
    free: Vec<Arc<Notify>>,
    closed: bool,
}

/// Correlates replies to waiters by DNS transaction id on a shared connection.
/// Shared by the framed TCP/DoT path and Do53-UDP. Replaces the old
/// `Arc<Mutex<HashMap<u16, oneshot::Sender>>>` with a pooled-`Notify` scheme that
/// avoids a per-query heap allocation while keeping the same id-keyed HashMap
/// (so any u16 may be live and the remove-on-timeout aliasing guard is intact).
pub struct Correlator {
    state: Mutex<CorrelatorState>,
    counter: AtomicU32,
}

impl Correlator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CorrelatorState {
                pending: HashMap::new(),
                free: Vec::new(),
                closed: false,
            }),
            counter: AtomicU32::new(0),
        })
    }

    /// Reserve a transaction id not currently outstanding, write it into the
    /// query header, and register a reply slot. Returns the id and the `Notify`
    /// to park on. Because at most the in-flight window of ids is ever live, the
    /// linear probe terminates quickly.
    pub fn register(&self, wire: &mut [u8]) -> (u16, Arc<Notify>) {
        let mut st = self.state.lock().unwrap();
        let mut id = self.counter.fetch_add(1, Ordering::Relaxed) as u16;
        while st.pending.contains_key(&id) {
            id = self.counter.fetch_add(1, Ordering::Relaxed) as u16;
        }
        wire[0] = (id >> 8) as u8;
        wire[1] = (id & 0xff) as u8;
        let notify = st.free.pop().unwrap_or_else(|| Arc::new(Notify::new()));
        st.pending.insert(
            id,
            Slot {
                notify: Arc::clone(&notify),
                response: None,
            },
        );
        (id, notify)
    }

    /// Cancel a registered query (e.g. the write failed before it was sent),
    /// recycling its slot.
    pub fn cancel(&self, id: u16) {
        let mut st = self.state.lock().unwrap();
        if let Some(slot) = st.pending.remove(&id) {
            st.free.push(slot.notify);
        }
    }

    /// Deliver a reply to its waiter, matched by the echoed transaction id.
    pub fn complete(&self, buf: &[u8]) {
        if buf.len() < 2 {
            return;
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let mut st = self.state.lock().unwrap();
        let Some(slot) = st.pending.get_mut(&id) else {
            return;
        };
        // A matching id with an unparseable header leaves the slot untouched; the
        // waiter reaps it on timeout (the reply is malformed, so there is nothing
        // to deliver).
        let Ok(header) = parse_response_header(buf, Some(id)) else {
            return;
        };
        slot.response = Some(DnsResponse {
            correlation: id,
            rcode: header.rcode,
            truncated: header.truncated,
            bytes_in: buf.len(),
        });
        let notify = Arc::clone(&slot.notify);
        drop(st);
        notify.notify_one();
    }

    /// Park until this query's reply lands, the connection closes, or `timeout`
    /// elapses, then recycle the slot. The wait loops because a recycled `Notify`
    /// can carry a stale permit (from a prior query whose timeout raced its
    /// reply); a spurious wake simply re-checks the slot and re-parks, bounded by
    /// the original deadline.
    pub async fn await_response(
        &self,
        id: u16,
        notify: Arc<Notify>,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let woke = tokio::time::timeout(remaining, notify.notified())
                .await
                .is_ok();
            let mut st = self.state.lock().unwrap();
            let slot = st
                .pending
                .get_mut(&id)
                .expect("slot stays registered until its waiter removes it");
            if let Some(response) = slot.response.take() {
                let slot = st.pending.remove(&id).unwrap();
                st.free.push(slot.notify);
                return Ok(response);
            }
            if st.closed {
                let slot = st.pending.remove(&id).unwrap();
                st.free.push(slot.notify);
                return Err(TransportError::ConnectionClosed);
            }
            if !woke {
                let slot = st.pending.remove(&id).unwrap();
                st.free.push(slot.notify);
                return Err(TransportError::Timeout);
            }
            // Spurious wake from a recycled permit: re-check under the loop.
        }
    }

    /// Mark the connection closed and wake every outstanding waiter so each
    /// returns `ConnectionClosed`. Called by the reader on socket EOF.
    pub fn close(&self) {
        let mut st = self.state.lock().unwrap();
        st.closed = true;
        let waiters: Vec<Arc<Notify>> =
            st.pending.values().map(|s| Arc::clone(&s.notify)).collect();
        drop(st);
        for notify in waiters {
            notify.notify_one();
        }
    }

    fn is_idle(&self) -> bool {
        self.state.lock().unwrap().pending.is_empty()
    }

    /// Wait for all outstanding queries to drain, bounded by `grace`. Shared by
    /// every `Connection::drain` impl (UDP and the framed TCP/DoT path).
    pub async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        while !self.is_idle() {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(mut read_half: R, correlator: Arc<Correlator>) {
    // One reusable buffer for every inbound frame; each reply is consumed by
    // complete() before the next read, so the buffer is free to overwrite.
    let mut msg = vec![0u8; MAX_DNS_MESSAGE_LEN];
    loop {
        let mut len_buf = [0u8; 2];
        if read_half.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if read_half.read_exact(&mut msg[..len]).await.is_err() {
            break;
        }
        correlator.complete(&msg[..len]);
    }
    correlator.close();
}

async fn write_loop<W: AsyncWrite + Unpin>(mut write_half: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if write_half.write_all(&frame).await.is_err() {
            break;
        }
        // Coalesce any frames already queued, then flush once the burst drains.
        // A buffering writer (rustls encrypts into its own buffer and only
        // opportunistically pushes to the socket) otherwise leaves the trailing
        // frames of a burst unsent until the next write, so those queries hang
        // until their timeout.
        while let Ok(frame) = rx.try_recv() {
            if write_half.write_all(&frame).await.is_err() {
                let _ = write_half.shutdown().await;
                return;
            }
        }
        if write_half.flush().await.is_err() {
            break;
        }
    }
    let _ = write_half.shutdown().await;
}

/// A length-prefixed (`[u16 len][message]`) DNS connection that pipelines many
/// queries over one stream and demultiplexes replies by transaction id. The
/// writer never blocks on a read, so submit and receive run concurrently. Shared
/// by Do53-TCP (raw `TcpStream`) and DoT (`TlsStream`).
pub struct FramedConn {
    writer: mpsc::Sender<Vec<u8>>,
    correlator: Arc<Correlator>,
    max_in_flight: usize,
}

impl FramedConn {
    pub fn spawn<R, W>(read_half: R, write_half: W, max_in_flight: usize) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let correlator = Correlator::new();
        tokio::spawn(read_loop(read_half, Arc::clone(&correlator)));
        // A bounded mpsc panics on capacity 0; clamp so any future caller that
        // derives the window from config cannot crash the connect path.
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(max_in_flight.max(1));
        tokio::spawn(write_loop(write_half, writer_rx));
        Self {
            writer: writer_tx,
            correlator,
            max_in_flight,
        }
    }
}

impl Connection for FramedConn {
    fn caps(&self) -> TransportCaps {
        TransportCaps {
            max_in_flight: self.max_in_flight,
        }
    }

    async fn exchange(
        &self,
        request: DnsRequest,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        if request.wire.len() < 2 {
            return Err(TransportError::Protocol("query shorter than header".into()));
        }
        let len = u16::try_from(request.wire.len())
            .map_err(|_| TransportError::Protocol("query exceeds TCP length field".into()))?;
        // Build the framed buffer (length prefix + message), then assign the
        // transaction id by patching it directly into the frame's copy of the
        // header (frame[2..4]); the shared `wire` is never mutated.
        let mut frame = Vec::with_capacity(request.wire.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&request.wire);
        let (id, notify) = self.correlator.register(&mut frame[2..]);

        if self.writer.send(frame).await.is_err() {
            self.correlator.cancel(id);
            return Err(TransportError::ConnectionClosed);
        }
        self.correlator.await_response(id, notify, timeout).await
    }

    async fn drain(&self, grace: Duration) {
        self.correlator.drain(grace).await;
    }
}
