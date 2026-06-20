use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot};
use wiresurge_transport::{ConnectTarget, connect_tcp, connect_udp};

use super::{Connection, DnsRequest, DnsResponse, Transport, TransportCaps, TransportError};
use crate::parse_response_header;

const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;
const UDP_IN_FLIGHT: usize = 1024;
const TCP_IN_FLIGHT: usize = 256;

type Pending = Arc<Mutex<HashMap<u16, oneshot::Sender<DnsResponse>>>>;

/// Reserve a transaction id that is not currently outstanding, write it into
/// the query header, and register the waiter under that id.
fn register(
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

fn complete(pending: &Pending, buf: &[u8]) {
    if buf.len() < 2 {
        return;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let sender = pending.lock().unwrap().remove(&id);
    if let Some(sender) = sender
        && let Ok(header) = parse_response_header(buf, id)
    {
        let _ = sender.send(DnsResponse {
            correlation: id,
            rcode: header.rcode,
            truncated: header.truncated,
            bytes_in: buf.len(),
        });
    }
}

async fn await_response(
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

pub struct UdpTransport;

pub struct UdpConn {
    socket: Arc<UdpSocket>,
    pending: Pending,
    counter: AtomicU32,
}

impl Transport for UdpTransport {
    type Conn = UdpConn;

    async fn connect(target: ConnectTarget) -> Result<UdpConn, TransportError> {
        let socket = Arc::new(
            connect_udp(&target)
                .await
                .map_err(|error| TransportError::Io(error.to_string()))?,
        );
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let reader_socket = Arc::clone(&socket);
        let reader_pending = Arc::clone(&pending);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MESSAGE_LEN];
            while let Ok(n) = reader_socket.recv(&mut buf).await {
                complete(&reader_pending, &buf[..n]);
            }
        });
        Ok(UdpConn {
            socket,
            pending,
            counter: AtomicU32::new(0),
        })
    }
}

impl Connection for UdpConn {
    fn caps(&self) -> TransportCaps {
        TransportCaps {
            max_in_flight: UDP_IN_FLIGHT,
        }
    }

    async fn exchange(
        &self,
        mut request: DnsRequest,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        if request.wire.len() < 2 {
            return Err(TransportError::Protocol("query shorter than header".into()));
        }
        let (id, rx) = register(&self.pending, &self.counter, &mut request.wire);
        if let Err(error) = self.socket.send(&request.wire).await {
            self.pending.lock().unwrap().remove(&id);
            return Err(TransportError::Io(error.to_string()));
        }
        await_response(&self.pending, id, rx, timeout).await
    }

    async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        while !self.pending.lock().unwrap().is_empty() {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

pub struct TcpTransport;

pub struct TcpConn {
    writer: mpsc::Sender<Vec<u8>>,
    pending: Pending,
    counter: AtomicU32,
}

impl Transport for TcpTransport {
    type Conn = TcpConn;

    async fn connect(target: ConnectTarget) -> Result<TcpConn, TransportError> {
        let stream = connect_tcp(&target)
            .await
            .map_err(|error| TransportError::Io(error.to_string()))?;
        let (read_half, write_half) = stream.into_split();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));

        let reader_pending = Arc::clone(&pending);
        tokio::spawn(read_loop(read_half, reader_pending));

        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(TCP_IN_FLIGHT);
        tokio::spawn(write_loop(write_half, writer_rx));

        Ok(TcpConn {
            writer: writer_tx,
            pending,
            counter: AtomicU32::new(0),
        })
    }
}

async fn read_loop(mut read_half: tokio::net::tcp::OwnedReadHalf, pending: Pending) {
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

async fn write_loop(mut write_half: OwnedWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if write_half.write_all(&frame).await.is_err() {
            break;
        }
    }
    let _ = write_half.shutdown().await;
}

impl Connection for TcpConn {
    fn caps(&self) -> TransportCaps {
        TransportCaps {
            max_in_flight: TCP_IN_FLIGHT,
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
        let deadline = tokio::time::Instant::now() + grace;
        while !self.pending.lock().unwrap().is_empty() {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}
