# Tickets

These tickets cut [`IMPLEMENTATION_SPEC.md`](../../IMPLEMENTATION_SPEC.md) into vertical slices, numbered in dependency order. Each ticket keeps its acceptance boxes and a `## Comments` section. The comments say what ran, where it ran and what the ticket deferred.

## Status

| # | Ticket | Status | Open |
|---|---|---|---|
| 01 | [Pin upstream versions](01-pin-upstream-versions.md) | done | the cloud-api-adaptor image digest |
| 02 | [Tracer: unlock from Share payloads, no VM](02-tracer-unlock-without-vm.md) | done | |
| 03 | [Tracer: two operators unlock through the relay, no VM](03-tracer-operators-unlock-through-relay.md) | done | |
| 04 | [Kata + swtpm environment](04-kata-swtpm-environment.md) | done | |
| 05 | [Share released over real attestation](05-share-released-over-real-attestation.md) | done | |
| 06 | [Trustee CVM unlocks on swtpm](06-trustee-cvm-unlocks-on-swtpm.md) | done | |
| 07 | [CI on every PR](07-ci-on-every-pr.md) | done | |
| 08 | [Share validation](08-share-validation.md) | done | |
| 09 | [Bundle and manifest integrity](09-bundle-and-manifest-integrity.md) | done | |
| 10 | [Sealed-config checks and safe extraction](10-sealed-config-checks-and-safe-extraction.md) | done | |
| 11 | [Crash recovery](11-crash-recovery.md) | done | |
| 12 | [Relay limits](12-relay-limits.md) | done | |
| 13 | [Operator Verifier hardening](13-operator-verifier-hardening.md) | done | |
| 14 | [Claim profiles for every TEE type](14-claim-profiles-for-every-tee.md) | done | |
| 15 | [cococtl mount](15-cococtl-mount.md) | done | the cococtl PR, after a tagged release |
| 16 | [Runbooks and supply chain](16-runbooks-and-supply-chain.md) | done | |
| 17 | [Real-TEE release gate](17-real-tee-release-gate.md) | **open** | a run on real TDX, SNP or Azure vTPM hardware |
| 18 | [Check Trustee's TLS certificate when sealing](18-check-trustee-tls-certificate.md) | done | |
| 19 | [Keep sealed secrets out of shell history](19-keep-secrets-out-of-shell-history.md) | done | |

Ticket 17 is the go/no-go. Until it passes, every claim profile stays untested and nobody runs a production unlock.

## Read these first

- [`IMPLEMENTATION_SPEC.md`](../../IMPLEMENTATION_SPEC.md): what to build, the phases, and acceptance tests AT-01 to AT-28.
- [`SECURITY_THREAT_MODEL.md`](../../SECURITY_THREAT_MODEL.md): claims, invariants and residual risks. Every change must keep these true.
- [`GLOSSARY.md`](../../GLOSSARY.md): use these terms in code, tests and tickets.
- [`docs/adr/`](../adr/): why the design looks the way it does. Read the ADR before you change a decision it records.
- [`docs/upstream-pins.md`](../upstream-pins.md): the exact upstream tags, commits and image digests. Build and test against these, not `main`.

## Working a ticket

Status moves `ready-for-agent` → `in-progress` → `done`. Take the lowest-numbered `ready-for-agent` ticket whose blockers are all `done`, and set it to `in-progress` before you start. Tick only the boxes you saw pass, and put the evidence in `## Comments`.

Tickets 02 and 03 were tracer bullets: the whole Unlock Ceremony in one Go test, before any VM. Ticket 06 made it work on swtpm. Tickets 08 to 14 each added one hardening property, end to end.

Decided after the reviews: we ship default secure configs (tickets 05 and 06) rather than track every upstream config option. The sealed-config checks (spec §3) stay as the guard.
