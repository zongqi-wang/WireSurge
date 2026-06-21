use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use wiresurge_transport::{ConnectTarget, connect_tcp, connect_udp, udp_proxy_prefix};

use super::framed::{Correlator, FramedConn};
use super::{Connection, DnsRequest, DnsResponse, Transport, TransportCaps, TransportError};
use crate::MAX_DNS_MESSAGE_LEN;

const UDP_IN_FLIGHT: usize = 1024;
const TCP_IN_FLIGHT: usize = 256;

pub struct UdpTransport;

pub struct UdpConn {
    socket: Arc<UdpSocket>,
    correlator: Arc<Correlator>,
    proxy_prefix: Vec<u8>,
}

impl Transport for UdpTransport {
    type Conn = UdpConn;

    async fn connect(target: ConnectTarget) -> Result<UdpConn, TransportError> {
        let proxy_prefix = udp_proxy_prefix(&target)
            .map_err(|error| TransportError::Io(error.to_string()))?
            .unwrap_or_default();
        let socket = Arc::new(
            connect_udp(&target)
                .await
                .map_err(|error| TransportError::Io(error.to_string()))?,
        );
        let correlator = Correlator::new();
        let reader_socket = Arc::clone(&socket);
        let reader_correlator = Arc::clone(&correlator);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_MESSAGE_LEN];
            while let Ok(n) = reader_socket.recv(&mut buf).await {
                reader_correlator.complete(&buf[..n]);
            }
            reader_correlator.close();
        });
        Ok(UdpConn {
            socket,
            correlator,
            proxy_prefix,
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
        request: DnsRequest,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        if request.wire.len() < 2 {
            return Err(TransportError::Protocol("query shorter than header".into()));
        }
        let prefix_len = self.proxy_prefix.len();
        let mut datagram = Vec::with_capacity(prefix_len + request.wire.len());
        datagram.extend_from_slice(&self.proxy_prefix);
        datagram.extend_from_slice(&request.wire);
        let (id, notify) = self.correlator.register(&mut datagram[prefix_len..]);
        if let Err(error) = self.socket.send(&datagram).await {
            self.correlator.cancel(id);
            return Err(TransportError::Io(error.to_string()));
        }
        self.correlator.await_response(id, notify, timeout).await
    }

    async fn drain(&self, grace: Duration) {
        self.correlator.drain(grace).await;
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
