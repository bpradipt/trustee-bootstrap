# EV-11: Pod recreation after unlock forgets everything

**Category:** partial failure
**Runs on:** kind + swtpm; `test/e2e/evals.sh ev11` scripts ways 1 and 4
**Covers:** invariant 8; residual risk "availability"; ADR 0002; spec §5 Restarts. AT-15 and AT-26 cover a helper restart and a Trustee container restart, not a new pod.

## Setup

An unlocked Trustee serving `workload-ok`, as `trustee-cvm.sh` leaves it after AT-24.

## Action

Recreate the Trustee CVM four ways, one after another. After each, check the expected state, then run a new Unlock Ceremony to get back to the setup.

1. `kubectl delete pod trustee-cvm`, then apply the same rendered `trustee-cvm.yaml`.
2. `kubectl drain --force --ignore-daemonsets` on the node, then `uncordon` it and apply the pod again.
3. Restart the kind node container, which reboots the node.
4. Kill the pod's QEMU process on the node. The pod object and its UID stay. Kubelet creates a new sandbox for the pod and runs the bootstrap-helper init container again.

## Expected

After each recreation:

- `status` shows a new `boot_id`, `state` `COLLECTING` and `accepted: []`.
- Trustee isn't Ready, and a new workload pod gets no resource. The script checks that the `trustee` Service has no endpoint.
- `check_host_view` finds the host side of the state volume empty.
- An Unlock Ceremony with the existing Operator Policies unlocks the new pod.

## Notes

`evals.sh ev11` scripts ways 1 and 4. They differ where it matters: way 1 deletes the pod object, and way 4 keeps it and replaces only the VM. Ways 2 and 3 stay manual. For the CVM, a drain evicts the pod the same way a delete removes it. Restarting a kind node under podman can change the node's IP and break the cluster for the runs that follow.

## Results

- 2026-11-12, branch `evals-scripted` on `f629a3a`, scratch VM, `test/e2e/evals.sh`: **pass** for ways 1 and 4. Nobody ran ways 2 and 3.
  - Each recreation was checked: first a pod delete, then a QEMU kill, which kept the pod UID and replaced the VM. `status` showed a new `boot_id`, `COLLECTING` and `accepted: []`.
  - Trustee wasn't Ready, the `trustee` Service had no address, and the host side of the state volume was empty.
  - Each time, Alice and Carol unlocked the new boot with their existing Operator Policies.
