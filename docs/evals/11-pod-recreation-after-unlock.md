# EV-11: Pod recreation after unlock forgets everything

**Category:** partial failure
**Runs on:** kind + swtpm
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
- Trustee isn't Ready, and a new workload pod gets no resource.
- `check_host_view` finds the host side of the state volume empty.
- An Unlock Ceremony with the existing Operator Policies unlocks the new pod.

## Results

None yet.
