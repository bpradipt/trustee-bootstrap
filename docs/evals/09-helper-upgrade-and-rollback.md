# EV-09: Upgrade the Bootstrap Helper and roll back

**Category:** upgrade
**Runs on:** kind + swtpm
**Covers:** [trustee-upgrade.md](../runbooks/trustee-upgrade.md), which ticket 16 never walked as a whole; threat "Trustee replaced after unlock"; AT-04; AT-10 at pod level

## Setup

- A 2-of-3 deployment unlocked with helper image v1. Alice and Bob hold Operator Policies in `~/trustee-policy`.
- Helper image v2: the same source built with an extra label, so it gets a new digest.
- For the config pass, a second bundle B, sealed from a new tree with the seal runbook.

## Action

**Image pass.** Walk trustee-upgrade.md steps 1 to 7 for a helper-only upgrade with the bundle unchanged. Inject two faults on the way:

1. Before step 4, Alice runs `approve` with her v1 policy against the v2 pod.
2. Before step 5, the Infrastructure Operator changes the helper digest in the rendered `trustee-cvm.yaml` by hand and skips genpolicy.

Then follow the runbook's *Roll back*.

**Config pass.** Upgrade to bundle B with new Operator Policies. Then the host recreates the pod with A in the ConfigMap, and Alice and Bob run `approve` with their B policies.

## Expected

- Fault 1: no release, and Alice's index stays out of `rejected`: her Operator Verifier refused.
- Fault 2: the event `CreateContainerRequest is blocked by policy`, and the helper never runs.
- Steps 5 to 7: the v2 pod unlocks with the new policies, and a workload with the current `kbs_cert` gets its resource.
- Roll back: the v1 pod unlocks again with the v1 policy directories, with no new review.
- Config pass: both indices land in `rejected`, and Trustee doesn't start on A.

## Results

None yet.
