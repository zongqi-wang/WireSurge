use tokio::io::split;
use wiresurge_transport::{ConnectTarget, connect_tls};

use super::framed::FramedConn;
use super::{Transport, TransportError};

const DOT_IN_FLIGHT: usize = 256;

pub struct DotTransport;

impl Transport for DotTransport {
    type Conn = FramedConn;

    async fn connect(target: ConnectTarget) -> Result<FramedConn, TransportError> {
        let stream = connect_tls(&target)
            .await
            .map_err(|error| TransportError::Io(error.to_string()))?;
        let (read_half, write_half) = split(stream);
        Ok(FramedConn::spawn(read_half, write_half, DOT_IN_FLIGHT))
    }
}
