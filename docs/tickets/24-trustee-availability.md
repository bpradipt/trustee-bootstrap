# 24: Keep Trustee available across replica restarts

**What to build:** first a decision, then the chosen option. Trustee runs on more than one Trustee CVM, so that losing one leaves the service up while the lost replica comes back. [ADR 0009](../adr/0009-trustee-availability.md) sets out two options, a quorum Unlock Ceremony for each replica (A) or replicas that unlock from a running replica (B), and the questions each leaves open.

**Why:** v1 runs one replica (ADR 0002). Each pod recreation leaves Trustee down until K Security Operators finish an Unlock Ceremony. Availability is the reason to run several KBS instances. Load balancing is secondary.

**Blocked by:** a decision on ADR 0009.

**Status:** needs-decision

**Spec:** ADR 0002, ADR 0009; `SECURITY_THREAT_MODEL.md` residual risks "Availability" and "An approval covers a configuration, not one VM"; [EV-02](../evals/02-host-splices-one-approval.md).

- [ ] ADR 0009 records the decision, after its open questions have answers and the chosen option has had an adversarial review.
- [ ] ADR 0002, the threat model and spec §5 describe the chosen design.
- [ ] The example deploys at least two replicas on different nodes, and documents how each one unlocks.
- [ ] An e2e test on swtpm: two replicas unlock, and workloads get their resources from either. Delete one, and the other keeps serving. The deleted one comes back unlocked, as the chosen option says.
- [ ] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments

- Opened 2026-11-13. The goal is availability. Option A needs no helper or CLI change, but each lost replica needs K Security Operators. Option B removes that, at the cost of four changes to the security claim that ADR 0009 lists.
