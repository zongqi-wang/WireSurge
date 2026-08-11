# ADR 0002: Numeric Domains and Scheduling Semantics

- **Status:** Proposed — defaults are conservative and reversible until the
  P0-A exit gate; owner review requested
- **Applies to:** P0-A day-1 decision 2; P0A-02, P0A-03, P0A-06

## Context

`RateGate::wait` computes `Duration::from_secs_f64(index as f64 / qps)`, which
panics when the quotient overflows `Duration` (a large finite `--count` with a
small `--qps`, or a very large finite `--duration-s`). A panic in the CLI
process exits without structured JSON. Separately, `WorkSource::next` checks
the run deadline *before* waiting on the rate gate, so a query whose scheduled
slot is past the deadline is still admitted and sent — the run overruns its
stated duration budget.

## Decision

Closed, documented numeric domains, validated at the admission boundary
(P0A-06) before any traffic starts:

| Input | Domain | Rejection |
|---|---|---|
| `--count` | `0..=u64::MAX` | none; `0` is a documented empty run (below) |
| `--duration-s` (`-l`) | `(0, 7 * 24 * 3600]` seconds | `0`, negative, non-finite, or > 7 days |
| `--qps` | `(0, 1_000_000]` | `0`, negative, non-finite, or > 1e6 |
| `--timeout-ms` | `1..=60_000` | `0` or > 60 s |
| `--connections` (`-c`) | `1..=1024` | `0` or > 1024 |
| `--in-flight` (`-q`) | `1..=1024` (clamped to transport capacity) | `0` or > 1024 |

Empty run: `--count 0` is a valid, documented empty run — the run admits no
work, reports truthful zero metrics, and succeeds (exit 0). It exists so
output-format and schema validation need no network fixture.

Scheduling semantics:

1. Admission compares the query's **scheduled slot** (`start + n/qps`) with
   the deadline **before** the rate-gate wait: a query whose slot is at or
   past the deadline is refused without waiting. `next()` returning `None` is
   permanent (count reached, slot budget or deadline passed — all monotonic),
   so actors stop requesting work exactly at the deadline.
2. All duration arithmetic uses checked operations (`checked_add`, saturating
   conversions); an overflowing computation yields a structured error, never a
   panic.
3. `Duration::from_secs_f64` is replaced by integer-based computation
   (microsecond ticks) so the QPS schedule cannot panic.
4. Missed-slot policy: if the runtime falls behind, later slots are **not**
   compressed — the rate gate sleeps to the scheduled instant, so the run
   duration truthfully reflects the requested rate.

## Consequences

- **Positive:** no accepted-domain input panics; duration budgets are
  truthful; the numeric domains are documented and testable.
- **Negative:** the 7-day duration cap and the 1e6 QPS cap reject inputs that
  previously ran (a huge `--duration-s` panicked before; it now fails with a
  structured error); existing tests that relied on the old behavior are
  updated.
- **Reversal:** widen a domain in the ADR and the admission validation
  together; tests pin the contract.
