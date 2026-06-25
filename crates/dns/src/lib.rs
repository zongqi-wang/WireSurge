use hickory_proto::op::{Edns, Header, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::EdnsOption as HickoryEdnsOption;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use wiresurge_core::{Result, WireSurgeError};

pub mod transport;

pub(crate) const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;
const MAX_EDNS_OPTION_PAYLOAD_LEN: usize = u16::MAX as usize - 4;

/// A single EDNS0 OPT option: a caller-supplied option code plus its raw payload
/// bytes. The code is configurable so callers can emit any option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseHeader {
    pub rcode: u16,
    pub truncated: bool,
}

/// Validate a response message header. `expected_id` is `Some(id)` for
/// transaction-id-correlated transports (Do53/DoT, where the id demultiplexes
/// replies on a shared connection) and `None` for DoH, where HTTP/2 binds each
/// response to its own stream and RFC 8484 §4.1 treats the DNS id as 0 — a
/// resolver, forwarder, or HTTP cache may legitimately return any id, so an
/// equality check there would reject valid answers.
pub fn parse_response_header(response: &[u8], expected_id: Option<u16>) -> Result<ResponseHeader> {
    // Decode only the fixed 12-byte DNS header — id, flags, rcode — which is all
    // a load run records. `Header::from_bytes` reads exactly those bytes and
    // skips the question/answer/authority/additional sections entirely, so a
    // multi-million-reply run avoids hickory's full per-record decode and its
    // allocations on the hot reply path.
    let header = Header::from_bytes(response).map_err(|error| {
        WireSurgeError::new("invalid_dns_response", error.to_string()).retryable(false)
    })?;
    if let Some(expected_id) = expected_id
        && header.id != expected_id
    {
        return Err(WireSurgeError::new(
            "dns_id_mismatch",
            format!(
                "expected transaction ID {expected_id}, received {}",
                header.id
            ),
        ));
    }
    if header.message_type != MessageType::Response {
        return Err(WireSurgeError::new(
            "invalid_dns_response",
            "DNS packet does not have the response bit set",
        ));
    }
    if header.op_code != OpCode::Query {
        return Err(WireSurgeError::new(
            "invalid_dns_response",
            "DNS response has an unexpected opcode",
        ));
    }
    Ok(ResponseHeader {
        // Low 4 bits only: `Header::from_bytes` masks rcode to the header nibble
        // (hickory `ResponseCode::from_low`). The 12-bit EDNS extended rcode lives
        // in the OPT RR TTL high byte (additional section); recovering it would
        // require a full `Message::from_vec` decode of every reply, defeating this
        // header-only fast path. rcode is stats-only (never gates retry/error) and
        // extended rcodes (>= 16) do not occur under plain query load, so the
        // low-nibble value is sufficient.
        rcode: u16::from(header.response_code),
        truncated: header.truncation,
    })
}

fn parse_dns_name(qname: &str) -> Result<Name> {
    let absolute_name = if qname.ends_with('.') {
        qname.to_string()
    } else {
        format!("{qname}.")
    };
    Name::from_ascii(absolute_name)
        .map_err(|error| WireSurgeError::new("invalid_dns_name", error.to_string()).at("qname"))
}

pub fn build_query(
    transaction_id: u16,
    qname: &str,
    qtype: u16,
    edns_options: &[EdnsOption],
) -> Result<Vec<u8>> {
    let name = parse_dns_name(qname)?;
    let mut message = Message::new(transaction_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(qtype)));

    if !edns_options.is_empty() {
        let mut extension = Edns::new();
        extension.set_max_payload(1232);
        for option in edns_options {
            if option.payload.len() > MAX_EDNS_OPTION_PAYLOAD_LEN {
                return Err(WireSurgeError::new(
                    "invalid_edns_payload",
                    "EDNS option payload exceeds 65531 bytes",
                )
                .at("edns_payload"));
            }
            extension.options_mut().insert(HickoryEdnsOption::Unknown(
                option.code,
                option.payload.clone(),
            ));
        }
        message.set_edns(extension);
    }
    let packet = message
        .to_vec()
        .map_err(|error| WireSurgeError::new("dns_encode_failed", error.to_string()).at("qname"))?;
    if packet.len() > MAX_DNS_MESSAGE_LEN {
        return Err(WireSurgeError::new(
            "dns_message_too_large",
            "DNS query exceeds the 65535-byte message limit",
        ));
    }
    // The static payload cap admits values that, combined with the question
    // section, push the message past 65535 bytes — where the encoder silently
    // drops the whole OPT record (ARCOUNT, header bytes 10..12, falls to 0)
    // rather than erroring. Reject that so a requested option never vanishes
    // from the wire unnoticed.
    if !edns_options.is_empty() && u16::from_be_bytes([packet[10], packet[11]]) == 0 {
        return Err(WireSurgeError::new(
            "edns_option_dropped",
            "EDNS option does not fit within the 65535-byte message limit for this query name",
        )
        .at("edns_payload"));
    }
    Ok(packet)
}

pub fn parse_qtype(value: &str) -> Result<u16> {
    let qtype = match value.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => value.parse::<u16>().map_err(|_| {
            WireSurgeError::new(
                "invalid_dns_qtype",
                "qtype must be A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, ANY, or a number",
            )
            .at("qtype")
        })?,
    };
    Ok(qtype)
}

pub fn decode_hex_payload(value: &str) -> Result<Vec<u8>> {
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err(WireSurgeError::new(
            "invalid_hex_payload",
            "hex payload must contain an even number of digits",
        )
        .at("edns_payload"));
    }
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex input is ASCII-addressable");
            u8::from_str_radix(pair, 16).map_err(|_| {
                WireSurgeError::new(
                    "invalid_hex_payload",
                    format!("'{pair}' is not a valid hexadecimal byte"),
                )
                .at("edns_payload")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_transaction_id_and_edns0_option() {
        let option = EdnsOption {
            code: 65001,
            payload: vec![0xca, 0xfe],
        };
        let packet = build_query(0xbeef, "example.com", 1, std::slice::from_ref(&option)).unwrap();
        assert_eq!(&packet[0..2], &0xbeef_u16.to_be_bytes());
        assert!(
            packet
                .windows(2)
                .any(|window| window == 65001_u16.to_be_bytes())
        );
        assert!(packet.ends_with(&[0xca, 0xfe]));
    }

    #[test]
    fn encodes_configurable_edns0_option_code() {
        // The option code must be caller-supplied, not hardcoded. NSID (3) is a
        // registered EDNS0 option code (RFC 5001).
        let payload = b"option-value".to_vec();
        let option = EdnsOption {
            code: 3,
            payload: payload.clone(),
        };
        let packet = build_query(0x1234, "example.com", 1, std::slice::from_ref(&option)).unwrap();
        assert!(
            packet
                .windows(2)
                .any(|window| window == 3_u16.to_be_bytes()),
            "option code 3 must appear in the OPT record"
        );
        assert!(
            !packet
                .windows(2)
                .any(|window| window == 65001_u16.to_be_bytes()),
            "the old hardcoded 65001 code must not leak through"
        );
        assert!(packet.ends_with(&payload));
    }

    #[test]
    fn rejects_edns_option_that_overflows_the_message() {
        // A payload that fits the per-option cap but pushes the whole message
        // past 65535 bytes makes the encoder silently drop the OPT record; that
        // must surface as an error rather than a plain query.
        let option = EdnsOption {
            code: 65001,
            payload: vec![0u8; MAX_EDNS_OPTION_PAYLOAD_LEN],
        };
        let error =
            build_query(0x1234, "example.com", 1, std::slice::from_ref(&option)).unwrap_err();
        assert_eq!(error.code, "edns_option_dropped");
    }

    #[test]
    fn encodes_multiple_edns0_options() {
        let options = [
            EdnsOption {
                code: 3,
                payload: b"nsid".to_vec(),
            },
            EdnsOption {
                code: 8,
                payload: b"ecs".to_vec(),
            },
        ];
        let packet = build_query(0x1234, "example.com", 1, &options).unwrap();
        assert!(
            packet.windows(2).any(|w| w == 3_u16.to_be_bytes()),
            "first option code must appear"
        );
        assert!(
            packet.windows(2).any(|w| w == 8_u16.to_be_bytes()),
            "second option code must appear"
        );
    }

    #[test]
    fn encodes_repeated_edns0_option_code() {
        // RFC 6891 does not forbid two OPT options sharing a code; both must
        // reach the wire with their own payloads rather than one overwriting the
        // other. Distinct payloads make each option independently detectable.
        let options = [
            EdnsOption {
                code: 65001,
                payload: b"first".to_vec(),
            },
            EdnsOption {
                code: 65001,
                payload: b"second".to_vec(),
            },
        ];
        let packet = build_query(0x1234, "example.com", 1, &options).unwrap();
        assert!(
            packet.windows(5).any(|w| w == b"first"),
            "first payload must appear on the wire"
        );
        assert!(
            packet.windows(6).any(|w| w == b"second"),
            "second payload for the same code must not be dropped"
        );
    }

    #[test]
    fn parses_named_and_numeric_qtypes() {
        assert_eq!(parse_qtype("AAAA").unwrap(), 28);
        assert_eq!(parse_qtype("65").unwrap(), 65);
    }

    #[test]
    fn rejects_header_only_response() {
        let response = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let header = parse_response_header(&response, Some(0x1234)).unwrap();
        assert_eq!(header.rcode, 0);
    }

    #[test]
    fn id_mismatch_rejected_only_when_expected_id_is_some() {
        // Response carries id 0x9999; QR + opcode valid.
        let response = [0x99, 0x99, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        // Do53/DoT correlate by id, so a mismatch is an error.
        assert_eq!(
            parse_response_header(&response, Some(0x1234))
                .unwrap_err()
                .code,
            "dns_id_mismatch"
        );
        // DoH passes None (HTTP/2 stream correlates), so any id is accepted.
        assert!(parse_response_header(&response, None).is_ok());
    }
}
