# EV-15: Canary sweep after a full unlock

**Category:** secret hygiene
**Runs on:** kind + swtpm; rerun on a real TEE in ticket 17
**Covers:** invariant 6; spec §0 requirement 6; the audit-record rules in the [runbooks README](../runbooks/README.md); e2e `check_host_view`, which checks only the state volume

## Setup

- A bundle sealed with a canary resource secret, `CANARY-<32 random hex>`.
- A checker shell that holds the search strings in memory only: the canary, Alice's and Bob's Share strings, and the base64 body of Trustee's `tls.key` and of the AS signer key.

## Action

1. Run a full Unlock Ceremony with Alice and Bob. Write each `approve`'s stdout and audit records to a file.
2. Include one rejected Share (a policy naming another bundle) and one Verifier refusal, so the error paths run too.
3. `workload-ok` fetches the canary. Restart the Trustee container once (AT-26).
4. From the checker shell, search for each string and for `AGE-SECRET-KEY-1` in:
   - every Kubernetes object: `kubectl get all,cm,secret,events -A -o yaml`, including pod status and termination messages;
   - `kubectl logs` of every container that allows it;
   - the kind node's file system and journal, including the containerd and Kata runtime directories;
   - each operator's `approve` output and audit log, `XDG_RUNTIME_DIR`, podman's storage, and `journalctl --user`;
   - every `status` response captured during the run.

## Expected

No search finds a match outside the two places a secret belongs: each operator's Share file, and the workload that fetched the canary.

## Notes

On swtpm the host can read guest memory, so this eval leaves it out. On a real TEE, AT-16 covers it.

Rootless podman may log a container's output to the user journal, and that log outlives `--rm`. The `journalctl --user` search checks that nothing the Operator Verifier prints lands there.

## Results

None yet.
