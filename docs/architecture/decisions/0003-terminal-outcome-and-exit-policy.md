# ADR 0003: Terminal Outcome and Exit Policy

- **Status:** Proposed — owner review requested
- **Applies to:** P0-A day-1 decision 3; P0A-05

## Context

Runner health, worker state, report health, and process exit can disagree:
HTTP transport failure and dry-run can leave runner records active; a DNS run
where every connection fails to connect still exits 0; an actor panic is
merged as a connection error and the run can still report success. The CLI has
no single typed outcome.

## Decision

One typed `RunOutcome` is the source of truth for runner records, reports,
and the process exit code. For the DNS load engine:

| Condition | Outcome | Exit |
|---|---|---|
| Run completed within budget; ≥ 1 query succeeded | `Succeeded` | 0 |
| Cancelled by signal | `Cancelled` | 130 (SIGINT) / 143 (SIGTERM) |
| Every connection failed / no query succeeded | `Failed` | 1 |
| Any actor task panicked | `Failed` (redacted diagnostic) | 1 |
| Admission/validation error | `Rejected` | 2 |

Rules:

1. A run is `Succeeded` only if at least one query was sent **and** at least
   one response was received and classified goodput per ADR 0004. The
   documented `--count 0` empty run (ADR 0002) succeeds with zero metrics.
2. A transport failure that stops the run (all connections dead, count or
   duration budget not met) is `Failed`, with a bounded, redacted
   representative diagnostic naming the first failing connection.
3. Runner and report records reach a terminal state on every path — success,
   failure, cancellation, validation rejection, and dry-run. A record in a
   non-terminal state after the process would exit is a bug.
4. The exit code mapping lives in one function used by both text and JSON
   output modes; stdout/stderr separation is preserved (`--output json`
   emits exactly one JSON value on stdout).
5. `std::process::exit` remains prohibited as the normal shutdown path.

Implementation status at the P0-A exit gate:

- The exit mapping is implemented for success (0), signal cancellation
  (130/143), zero-goodput failure (1), and admission rejection (2), and
  runner records reach a terminal state on every path (rule 3).
- The single typed `RunOutcome` (Decision), the bounded redacted
  representative diagnostic (rule 2), and the actor-panic row (table) are
  deferred to a later P0-A slice; a panicked actor task is currently merged
  as a connection error, so a run whose other actors produced goodput can
  still exit 0.

## Consequences

- **Positive:** exit codes and reports become truthful; scripts and CI can
  rely on the mapping; the "all-connect-failed success" and "active runner
  after failure" defects close.
- **Negative:** some previously-successful invocations (e.g., load against a
  dead target) now exit non-zero — that is the intended correction.
- **Reversal:** adjust the mapping table; tests pin each row.
