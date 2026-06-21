use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::{Connection, DnsRequest, DnsResponse, TransportCaps, TransportError};
use crate::parse_response_header;

/// Map from outstanding transaction id to the waiter expecting that reply.
pub type Pending = Arc<Mutex<HashMap<u16, oneshot::Sender<DnsResponse>>>>;

/// Reserve a transaction id that is not currently outstanding, write it into the
/// query header, and register the waiter under that id. Because at most the
/// in-flight window of ids is ever live, the linear probe terminates quickly and
/// ids stay unique among queries actually in flight on this connection.
pub fn register(
    pending: &Pending,
    counter: &AtomicU32,
    wire: &mut [u8],
) -> (u16, oneshot::Receiver<DnsResponse>) {
    let (tx, rx) = oneshot::channel();
    let mut map = pending.lock().unwrap();
    let mut id = counter.fetch_add(1, Ordering::Relaxed) as u16;
    while map.contains_key(&id) {
        id = counter.fetch_add(1, Ordering::Relaxed) as u16;
    }
    wire[0] = (id >> 8) as u8;
    wire[1] = (id & 0xff) as u8;
    map.insert(id, tx);
    (id, rx)
}

pub fn complete(pending: &Pending, buf: &[u8]) {
    if buf.len() < 2 {
        return;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let sender = pending.lock().unwrap().remove(&id);
    if let Some(sender) = sender
        && let Ok(header) = parse_response_header(buf, Some(id))
    {
        let _ = sender.send(DnsResponse {
            correlation: id,
            rcode: header.rcode,
            truncated: header.truncated,
            bytes_in: buf.len(),
        });
    }
}

pub async fn await_response(
    pending: &Pending,
    id: u16,
    receiver: oneshot::Receiver<DnsResponse>,
    timeout: Duration,
) -> Result<DnsResponse, TransportError> {
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(TransportError::ConnectionClosed),
        Err(_) => {
            pending.lock().unwrap().remove(&id);
            Err(TransportError::Timeout)
        }
    }
}

/// Wait for all outstanding queries to drain, bounded by `grace`. Shared by
/// every `Connection::drain` impl (UDP and the framed TCP/DoT path).
pub async fn drain_pending(pending: &Pending, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    while !pending.lock().unwrap().is_empty() {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn read_loop<R: AsyncRead + Unpin>(mut read_half: R, pending: Pending) {
    loop {
        let mut len_buf = [0u8; 2];
        if read_half.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        if read_half.read_exact(&mut msg).await.is_err() {
            break;
        }
        complete(&pending, &msg);
    }
    pending.lock().unwrap().clear();
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
    pending: Pending,
    counter: AtomicU32,
    max_in_flight: usize,
}

impl FramedConn {
    pub fn spawn<R, W>(read_half: R, write_half: W, max_in_flight: usize) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(read_loop(read_half, Arc::clone(&pending)));
        // A bounded mpsc panics on capacity 0; clamp so any future caller that
        // derives the window from config cannot crash the connect path.
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(max_in_flight.max(1));
        tokio::spawn(write_loop(write_half, writer_rx));
        Self {
            writer: writer_tx,
            pending,
            counter: AtomicU32::new(0),
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
        mut request: DnsRequest,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        let len = u16::try_from(request.wire.len())
            .map_err(|_| TransportError::Protocol("query exceeds TCP length field".into()))?;
        if request.wire.len() < 2 {
            return Err(TransportError::Protocol("query shorter than header".into()));
        }
        let (id, rx) = register(&self.pending, &self.counter, &mut request.wire);
        let mut frame = Vec::with_capacity(request.wire.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&request.wire);

        if self.writer.send(frame).await.is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(TransportError::ConnectionClosed);
        }
        await_response(&self.pending, id, rx, timeout).await
    }

    async fn drain(&self, grace: Duration) {
        drain_pending(&self.pending, grace).await;
    }
}
