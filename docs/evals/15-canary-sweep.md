# EV-15: Canary sweep after a full unlock

**Category:** secret hygiene
**Runs on:** kind + swtpm, `test/e2e/evals.sh ev15`; rerun on a real TEE in ticket 17
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

A search that finds nothing proves something only if it works. `evals.sh` first checks that the same search finds the canary where it belongs, in the workload's own log, through `kubectl` and on the node's disk. It then reports how many lines it searched on each surface, so an empty source can't pass unnoticed.

## Results

- 2026-11-12, branch `evals-scripted` on `f629a3a`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals.sh`: **pass**.
  - The run sealed a random canary, then exercised both error paths, an unlock, a workload fetch and a Trustee container restart.
  - The positive controls found the canary in the workload's log.
  - No surface held the canary, a Share, a key body or an age identity. Lines searched:

    | Surface | Lines searched |
    |---|---|
    | Kubernetes objects and events | 24,154 |
    | Container logs, except the workload's own | 5,017 |
    | The node's journal | 41,784 |
    | `approve` output and audit records | 42 |
    | `status` responses | 30 |
    | The operators' user journal | 51,334 |
    | The node's file system | not counted: a file search |
    | The operators' runtime directory and podman storage | not counted: a file search |

  - Guest memory was out of scope on swtpm.
