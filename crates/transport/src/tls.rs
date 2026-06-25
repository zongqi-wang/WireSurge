use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use wiresurge_core::{Result, WireSurgeError};

use super::{AppProto, ConnectTarget};

pub struct TlsParams {
    pub proto: AppProto,
    pub insecure: bool,
}

/// Build a shared rustls `ClientConfig` for one protocol. `ring` is the explicit
/// provider; ALPN advertises the protocol; SNI and TLS 1.2 fallback
/// are enabled because the target listener may not offer TLS 1.3.
pub fn build_client_config(params: &TlsParams) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| WireSurgeError::new("tls_config_failed", error.to_string()))?;

    let mut config = if params.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(provider)))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(native_roots()?)
            .with_no_client_auth()
    };

    config.alpn_protocols = vec![params.proto.alpn().to_vec()];
    config.enable_sni = true;
    config.resumption = rustls::client::Resumption::in_memory_sessions(256);
    Ok(Arc::new(config))
}

fn native_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(WireSurgeError::new(
            "no_root_certs",
            "no native root certificates were loaded; pass --insecure for self-signed targets",
        ));
    }
    Ok(roots)
}

pub(crate) fn server_name(target: &ConnectTarget) -> Result<ServerName<'static>> {
    let name = target
        .sni
        .clone()
        .unwrap_or_else(|| target.tcp_addr.ip().to_string());
    // rustls rejects a bracketed IPv6 ServerName (`[::1]`), so unbracket a
    // user-supplied `--sni` IP literal and build the IP ServerName directly;
    // DNS names fall through to the string parse unchanged.
    let unbracketed = name
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&name);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return Ok(ServerName::from(ip));
    }
    ServerName::try_from(name)
        .map_err(|error| WireSurgeError::new("invalid_sni", error.to_string()).at("sni"))
}

/// Relaxed-ALPN (flame lesson): exact match proceeds; no ALPN proceeds only when
/// relaxed; a conflicting protocol is a hard error.
pub(crate) fn check_alpn(
    stream: &TlsStream<TcpStream>,
    proto: AppProto,
    relaxed: bool,
) -> Result<()> {
    match stream.get_ref().1.alpn_protocol() {
        Some(negotiated) if negotiated == proto.alpn() => Ok(()),
        Some(other) => Err(WireSurgeError::new(
            "alpn_mismatch",
            format!(
                "peer negotiated {:?}, expected {:?}",
                String::from_utf8_lossy(other),
                String::from_utf8_lossy(proto.alpn())
            ),
        )),
        None if relaxed => Ok(()),
        None => Err(WireSurgeError::new(
            "alpn_absent",
            "peer negotiated no ALPN; pass --alpn-relaxed to assume the configured protocol",
        )),
    }
}

#[derive(Debug)]
struct NoVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn target_with_sni(addr: &str, sni: Option<&str>) -> ConnectTarget {
        let mut target = ConnectTarget::new(addr.parse::<SocketAddr>().unwrap());
        target.sni = sni.map(str::to_string);
        target
    }

    #[test]
    fn server_name_defaults_ipv6_peer_to_ip_address() {
        let name = server_name(&target_with_sni("[2606:4700:4700::1111]:853", None)).unwrap();
        assert!(matches!(name, ServerName::IpAddress(_)));
    }

    #[test]
    fn server_name_accepts_bare_ipv6_sni() {
        let name = server_name(&target_with_sni(
            "[2606:4700:4700::1111]:853",
            Some("2606:4700:4700::1111"),
        ))
        .unwrap();
        assert!(matches!(name, ServerName::IpAddress(_)));
    }

    #[test]
    fn server_name_accepts_bracketed_ipv6_sni() {
        let name = server_name(&target_with_sni(
            "[2606:4700:4700::1111]:853",
            Some("[2606:4700:4700::1111]"),
        ))
        .unwrap();
        assert!(matches!(name, ServerName::IpAddress(_)));

        let loopback = server_name(&target_with_sni("[::1]:853", Some("[::1]"))).unwrap();
        assert!(matches!(loopback, ServerName::IpAddress(_)));
    }

    #[test]
    fn server_name_keeps_dns_name() {
        let name = server_name(&target_with_sni("127.0.0.1:853", Some("dns.example"))).unwrap();
        assert!(matches!(name, ServerName::DnsName(_)));
    }
}
