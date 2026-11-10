# Trustee bootstrap: spec pointer

The spec lives at the repo root, so there is one copy:

- `IMPLEMENTATION_SPEC.md`: what to build, the phases, and acceptance tests AT-01 to AT-28.
- `SECURITY_THREAT_MODEL.md`: claims, invariants and residual risks. Every change must keep these true.
- `GLOSSARY.md`: use these terms in code, tests and tickets.
- `docs/adr/`: why the design looks the way it does. Read the ADR before you change a decision it records.
- `docs/upstream-pins.md`: the exact upstream tags, commits and image digests. Build and test against these, not `main`.

Tickets are in `issues/`: vertical slices, numbered in dependency order. Status moves `ready-for-agent` → `in-progress` → `done`. Take the lowest-numbered `ready-for-agent` ticket whose blockers are all `done`, and set it to `in-progress` before you start.

Tickets 02 and 03 are tracer bullets: the whole Unlock Ceremony working in one Go test, before any VM. Ticket 06 makes it work on swtpm. Tickets 08 to 14 each add one hardening property, end to end, and most can run in parallel.

Decided after the reviews: we ship default secure configs (tickets 05 and 06) rather than tracking every upstream config option. The sealed-config checks (spec §3) stay as the guard.
