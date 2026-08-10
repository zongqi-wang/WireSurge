# ADR 0004: DNS Goodput Classification and Metric Units

- **Status:** Proposed — owner review requested
- **Applies to:** P0-A day-1 decision 4; P0A-04

## Context

The fast response path decodes only the fixed 12-byte DNS header and masks
RCODE to its low 4 bits, so EDNS extended RCODEs are lost (a BADVERS response,
extended RCODE 16, is counted as NOERROR) and header validity is conflated
with matching-response validity and with goodput. Metric units are
inconsistent across fields (elapsed seconds, milliseconds, microseconds).

## Decision

Three distinct classifications, in order:

1. **Header valid** — 12-byte header parses, QR=1, OPCODE=Query.
2. **Matching response** — header valid, transaction ID equals the sent ID
   (Do53/DoT) or the question section matches the sent question (DoH, ID
   always 0), and the question matches what was sent.
3. **Goodput** — a matching response whose RCODE policy classifies it as
   successful.

RCODE policy (default, configurable later):

| RCODE (incl. extended) | Class |
|---|---|
| 0 NOERROR | Goodput |
| 3 NXDOMAIN, 5 REFUSED, 2 SERVFAIL, 1 FORMERR | Received, not goodput |
| 16+ extended (BADVERS, BADCOOKIE, …) | Received, classified by value — never NOERROR |

The OPT pseudo-record is scanned for the extended RCODE high bits (RFC 6891
§6.1.3) when present.

Metric units (documented on every emitted field):

| Field | Unit |
|---|---|
| `elapsed_s`, `duration_s`, QPS fields | seconds, per-second rates |
| latency histogram | microseconds |
| `timeout_ms`, `progress_interval_ms` | milliseconds |
| `bytes_in` | bytes |

`noerror_qps` is renamed to the goodput rate (e.g. `goodput_qps`) and counts
only classified goodput; `recv_qps` counts all received matching responses.
Both are computed against the true run duration.

## Consequences

- **Positive:** BADVERS/REFUSED/SERVFAIL stop inflating success metrics; the
  goodput contract becomes testable; units are unambiguous.
- **Negative:** JSON field renames are a breaking change for any consumer —
  acceptable pre-alpha, noted in the release notes.
- **Reversal:** RCODE policy can be made configurable without changing the
  classification layers.
