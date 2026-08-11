# Architecture Decision Records

Day-1 decisions from the [P0-A immediate plan](../../implementation-plan.md).
Each record states the decision, its context, and its consequences. Records
marked **Proposed** carry defaults that are reversible until the P0-A exit gate.

| ADR | Decision | Status |
|---|---|---|
| [0001 License and contribution model](0001-license-and-contribution-model.md) | AGPL-3.0 | Accepted (2026-08-10) |
| [0002 Numeric domains and scheduling semantics](0002-numeric-domains-and-scheduling.md) | Conservative closed numeric domains; deadline checked before rate admission | Proposed |
| [0003 Terminal outcome and exit policy](0003-terminal-outcome-and-exit-policy.md) | Typed outcome; run fails when no query succeeds; signal exit codes | Proposed |
| [0004 DNS goodput and metric units](0004-dns-goodput-and-metric-units.md) | Matching-valid response classification with explicit RCODE policy; documented units | Proposed |
| [0005 Resource limits and admission](0005-resource-limits-and-admission.md) | `ValidatedLoadPlan` + `ResourceBudget` as the only engine entry | Proposed |
