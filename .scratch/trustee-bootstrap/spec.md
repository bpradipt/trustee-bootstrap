# Trustee bootstrap: spec pointer

The spec lives at the repo root, so there is one copy:

- `IMPLEMENTATION_SPEC.md`: what to build, the phases, and acceptance tests AT-01 to AT-28.
- `SECURITY_THREAT_MODEL.md`: claims, invariants and residual risks. Every change must keep these true.
- `GLOSSARY.md`: use these terms in code, tests and tickets.
- `docs/adr/`: why the design looks the way it does. Read the ADR before you change a decision it records.

Tickets are in `issues/`, numbered in dependency order. Status moves `open` → `in-progress` → `done`. Take the lowest-numbered `open` ticket whose `Blocked by` tickets are all `done`, and set it to `in-progress` before you start.

Decided after the reviews: we ship a default secure Trustee config (ticket 05) rather than tracking every upstream config option. The sealed-config checks (spec §3) stay as the guard.
