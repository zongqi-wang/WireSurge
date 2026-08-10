# ADR 0005: Resource Limits and Admission

- **Status:** Proposed — owner review requested
- **Applies to:** P0-A day-1 decision 5; P0A-02, P0A-06

## Context

`run_load_with_progress` accepts a plain `LoadConfig` after a field-level
`validate()`; there is no aggregate admission boundary. Configured task,
connection, and corpus memory envelopes are unsafe: the engine can be asked
for 1024 connections × 1024 in-flight × 64 KB messages with no aggregate
check, and there is no shared concept of "how much may this run consume".

## Decision

One internal admission module (engine crate) owns the only constructors:

- `ValidatedLoadPlan` — private fields, constructed only by
  `ValidatedLoadPlan::new(LoadConfig) -> Result<ValidatedLoadPlan, LoadError>`
  after domain checks (ADR 0002) and aggregate checks below.
- `ResourceBudget` — computed from the plan: estimated in-flight bytes
  (connections × in-flight × max wire message length), corpus size, and
  encoded payload expansion.

Aggregate limits (conservative, documented, and enforced):

| Resource | Limit |
|---|---|
| `connections × in-flight` | ≤ 4096 total in-flight queries |
| in-flight bytes estimate | ≤ 256 MiB |
| corpus rows | ≤ 10,000,000 |
| encoded payload expansion (total wire bytes) | ≤ 512 MiB |
| wall-clock run length | ≤ 7 days (ADR 0002) |

The engine entry points accept only `ValidatedLoadPlan`; `LoadConfig` is a
CLI-side transfer type and cannot be executed directly. A rejected plan
produces a structured `LoadError` with field paths, never a panic, and the
CLI maps it to exit code 2 (ADR 0003).

## Consequences

- **Positive:** the engine cannot be asked to admit unbounded work; safety
  decisions are centralized and testable; P0A-06 closes.
- **Negative:** the CLI's `LoadConfig -> ValidatedLoadPlan` conversion adds a
  seam the HTTP path will later share; the plan type is internal for now.
- **Reversal:** adjust limits in the ADR and the module together; the
  aggregate tests pin the boundary.
