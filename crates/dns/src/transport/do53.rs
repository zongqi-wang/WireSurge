use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use tokio::net::UdpSocket;
use wiresurge_transport::{ConnectTarget, connect_tcp, connect_udp};

use super::framed::{FramedConn, Pending, await_response, complete, drain_pending, register};
use super::{Connection, DnsRequest, DnsResponse, Transport, TransportCaps, TransportError};
use crate::MAX_DNS_MESSAGE_LEN;

const UDP_IN_FLIGHT: usize = 1024;
const TCP_IN_FLIGHT: usize = 256;

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
        let pending: Pending = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
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
        drain_pending(&self.pending, grace).await;
    }
}

pub struct TcpTransport;

impl Transport for TcpTransport {
    type Conn = FramedConn;

    async fn connect(target: ConnectTarget) -> Result<FramedConn, TransportError> {
        let stream = connect_tcp(&target)
            .await
            .map_err(|error| TransportError::Io(error.to_string()))?;
        let (read_half, write_half) = stream.into_split();
        Ok(FramedConn::spawn(read_half, write_half, TCP_IN_FLIGHT))
    }
}
