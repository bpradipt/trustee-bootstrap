# EV-03: Host ignores a withdrawal

**Category:** hostile host
**Runs on:** kind + swtpm, with an attacker mode that rewrites `status`
**Covers:** residual risk "released Shares are irrevocable for a live boot"; [withdraw-approval.md](../runbooks/withdraw-approval.md); AT-12; spec §5 COLLECTING

## Setup

- A 2-of-3 deployment with Approved Bundle A. Alice released her Share, and `status` lists her index in `accepted`.
- Alice withdraws her approval of A and now approves only bundle B. Carol rebuilds her Operator Policy for B, as step 2 of the runbook says. Bob, compromised, keeps his policy for A.
- The host keeps the old pod running. It answers `status` on the endpoint with a forged body: a new `boot_id`, `COLLECTING`, `accepted: []`. It routes every relay to the old pod.

## Action

1. Alice and Carol follow withdraw-approval.md steps 1 to 4. Step 4 shows them the forged status.
2. Carol runs `approve` with her policy for B.
3. Read the old pod's real status through `kubectl port-forward` to the pod.
4. Bob runs `approve` with his policy for A.

## Expected

- After step 2, the old pod lists Carol's index in `rejected`: her Share names B, and the pod holds A in memory.
- After step 3, the old pod is still `COLLECTING` with only Alice's index in `accepted`, and Trustee hasn't started.
- After step 4, the old pod unlocks A. This is the documented residual risk: it takes a cooperating host and a compromised Security Operator.

The eval fails if A unlocks before step 4, or if Carol's Share counts toward A.

## Notes

The second-person checks in withdraw-approval.md compare `boot_id` and the pod UID. A host that forges `status` defeats the `boot_id` check, so record whether the runbook gives the Security Operators any check that the host can't forge.

## Results

None yet.
