use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use wiresurge_transport::ConnectTarget;

pub mod do53;
pub mod doh;
pub mod dot;
pub mod framed;

/// One prepared query. `wire` is the full DNS message, shared immutably across
/// every query that selects the same corpus row; the connection assigns a
/// transaction id at send time by copying the message into its own send buffer
/// and patching `[0..2]` there, so the shared buffer is never mutated and ids
/// stay unique among the queries actually outstanding on that connection.
#[derive(Clone, Debug)]
pub struct DnsRequest {
    pub wire: Arc<[u8]>,
}

#[derive(Debug)]
pub struct DnsResponse {
    pub correlation: u16,
    pub rcode: u16,
    pub truncated: bool,
    pub bytes_in: usize,
}

#[derive(Debug)]
pub enum TransportError {
    Timeout,
    Io(String),
    Protocol(String),
    ConnectionClosed,
}

/// Static capabilities of a freshly established connection.
#[derive(Debug, Clone, Copy)]
pub struct TransportCaps {
    pub max_in_flight: usize,
}

/// A connection that can carry many in-flight queries concurrently. `exchange`
/// takes `&self` so a single connection can be driven by many tasks at once;
/// correlation back to the right caller happens internally (transaction id for
/// Do53/DoT, stream id for DoH).
pub trait Connection: Send + Sync + 'static {
    fn caps(&self) -> TransportCaps;

    fn exchange(
        &self,
        request: DnsRequest,
        timeout: Duration,
    ) -> impl Future<Output = Result<DnsResponse, TransportError>> + Send;

    /// True once the connection is permanently unusable (peer GOAWAY, driver
    /// gone, socket closed). The load engine consults this to stop feeding a
    /// dead connection instead of hot-spinning on synchronous send failures —
    /// it matters most for DoH, whose `exchange` returns `ConnectionClosed`
    /// instantly once the HTTP/2 driver exits. Transports that block on a
    /// socket per query (Do53/DoT) cannot hot-spin and keep the default.
    fn is_closed(&self) -> bool {
        false
    }

    /// Stop accepting new work and let in-flight queries finish within `grace`.
    fn drain(&self, grace: Duration) -> impl Future<Output = ()> + Send;
}

pub trait Transport: Send + Sync + 'static {
    type Conn: Connection;

    fn connect(
        target: ConnectTarget,
    ) -> impl Future<Output = Result<Self::Conn, TransportError>> + Send;
}
