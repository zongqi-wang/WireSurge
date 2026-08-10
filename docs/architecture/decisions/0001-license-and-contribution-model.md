# ADR 0001: License and Contribution Model

- **Status:** Accepted — 2026-08-10 (repository owner decision)
- **Applies to:** P0-A day-1 decision 1

## Context

The repository is inconsistent: `LICENSE` contains the GNU Affero General
Public License v3.0 text, while `Cargo.toml` declares `license = "MIT OR
Apache-2.0"` in `[workspace.package]`. Packaging, crates.io publishing, and
license scanners read the Cargo metadata; downstream users and reviewers read
the LICENSE file. Two licenses advertised under one name is a release-blocking
defect (P0A-01) and a legal ambiguity for contributors.

The product is a terminal-native, local-first CLI. It has no hosted service
component, so the AGPL's network-copyleft clause is not load-bearing, but the
license choice belongs to the repository owner.

## Decision

**AGPL-3.0 is the project license.** The `LICENSE` file is the source of
truth. All license metadata is aligned to it:

- `Cargo.toml` `[workspace.package] license = "AGPL-3.0"`.
- Every crate `Cargo.toml` that overrides or duplicates the license field
  carries `AGPL-3.0`.
- Help output, `wiresurge schema`, README, and documentation that state a
  license name state AGPL-3.0.
- The dependency-license policy (`deny.toml`) already governs *third-party*
  licenses and is unchanged.

Contribution model: contributors retain copyright of their work; the
repository tracks a single project license. No CLA is introduced at P0-A.

## Consequences

- **Positive:** metadata and LICENSE agree; the audit's P0A-01 finding closes;
  the alpha artifact can be published with a truthful license declaration.
- **Negative:** AGPL-3.0 is a strong copyleft that some downstream consumers
  avoid; embedding WireSurge in proprietary tooling requires care.
- **Reversal:** changing to MIT OR Apache-2.0 later requires replacing the
  LICENSE file and re-aligning metadata in one commit; no code changes.
