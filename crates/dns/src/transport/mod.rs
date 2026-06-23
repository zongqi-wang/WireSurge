use std::future::Future;
use std::time::Duration;

use wiresurge_transport::ConnectTarget;

pub mod do53;
pub mod doh;
pub mod dot;
pub mod framed;

/// One prepared query. `wire` is the full DNS message, owned per query (each
/// `WorkSource::next` hands out a fresh `Vec<u8>` cloned from the prebuilt corpus
/// buffer). The connection assigns a transaction id at send time by patching
/// `wire[0..2]` in place (the UDP no-prefix fast path) or in the framed/proxied
/// send buffer's copy of the header. Owning the buffer avoids the shared-`Arc`
/// atomic refcount traffic that regressed DoH throughput (PR #8 / 8ff5f9e).
#[derive(Clone, Debug)]
pub struct DnsRequest {
    pub wire: Vec<u8>,
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
