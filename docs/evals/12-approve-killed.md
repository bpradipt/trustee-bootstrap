# EV-12: `approve` killed with SIGKILL

**Category:** partial failure
**Runs on:** an operator workstation with rootless podman, with the attacker in `hold` mode in front of a real helper; `test/e2e/evals-cluster.sh ev12`
**Covers:** spec §0 requirement 3; invariant 6 on the operator side; AT-18, which covers success, failure, SIGINT and SIGTERM

## Setup

- A valid Operator Policy and Share file.
- `test/e2e/attacker` in `hold` mode at the endpoint, so the relay stays open and `approve` waits with its Operator Verifier running.

## Action

1. Start `approve` and wait for the `relay_opened` audit record.
2. Send SIGKILL to the `approve` process only, as an OOM kill or a crash would.
3. Start a second `approve` with the same policy.

## Expected

After step 2, or at the latest when step 3 starts:

- No KBS container from the first run remains (`podman ps -a`).
- Nothing listens on the first run's `127.0.0.1` port.
- No run directory holding the Share payload remains under `XDG_RUNTIME_DIR`.

## Notes

Before [ticket 20](../tickets/20-clean-up-after-a-killed-approve.md), `pkg/verifier` set no `Pdeathsig` on the engine, and `approve` didn't look for an earlier run's leftovers. A SIGKILLed `approve` left its container serving the Share payload on `127.0.0.1`, and the payload stayed on the tmpfs until logout. The first run of this eval didn't show that, though: its `kill -9` missed `approve` (see Results).

Now the kernel sends the engine SIGTERM when `approve` dies, so the container and the listener go within seconds. Each run holds its directory locked, and the next `approve` removes a directory that no live run holds, along with its container, and logs `verifier_swept`. The eval checks the container and the listener 5 s after the SIGKILL, and everything after the second `approve`. A setuid engine, such as `sudo podman`, clears `Pdeathsig`; with one, the container also waits for the next `approve`.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **fail**, as expected. After the SIGKILL, and still after a second `approve`, three things remained: the KBS container, its listener on `127.0.0.1`, and the run directory holding the Share payload. See [ticket 20](../tickets/20-clean-up-after-a-killed-approve.md). The eval removes them afterwards.
- 2026-11-13, branch `approve-cleanup`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh ev12`, with [ticket 20](../tickets/20-clean-up-after-a-killed-approve.md)'s fix: **pass**. 5 s after the SIGKILL, the run directory remained, without its container or listener. The second `approve` removed it and logged `verifier_swept`. This run also fixed the eval: before, `kill -9` reached a bash subshell, not `approve`, so the 2026-11-12 result above reflects a live `approve`.
