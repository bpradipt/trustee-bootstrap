# 20: Clean up after a killed approve

**What to build:** when `approve` dies without running its cleanup, after a SIGKILL, an OOM kill or a crash, its Operator Verifier doesn't keep running and its run directory doesn't stay behind. At the latest, the next `approve` removes both before it starts.

**Why:** [EV-12](../evals/12-approve-killed.md) killed `approve` with SIGKILL while its Operator Verifier served a relay. Three things remained, and they still remained after a second `approve`:

- the KBS container, running;
- its listener on `127.0.0.1`;
- the run directory under `$XDG_RUNTIME_DIR`, with the Share payload in it.

`pkg/verifier` starts the engine with `exec.CommandContext` and stops it from a deferred call and a signal handler (ticket 13, AT-18). A SIGKILL skips both. The `podman run --rm` child is reparented and keeps the container up. Nothing looks for an earlier run's leftovers.

The exposure stays on the Security Operator's own workstation, which the threat model trusts. The leftover KBS releases the Share only to evidence that passes the operator's policy, and its admin key is gone. Still, the Share payload sits in plaintext on the tmpfs until logout, and a KBS keeps serving it long after the operator thinks the run ended. That breaks AT-18's intent, "no listener, container or Share temp file remains".

**Options to weigh:**

- **Tie the engine to `approve`'s life.** Set `SysProcAttr.Pdeathsig` to SIGTERM on the engine process, so the kernel signals `podman run` when `approve` dies. `podman run --rm` then stops and removes the container. Go's Pdeathsig fires when the creating thread exits, not the process (golang/go#27505), so the start must run on a goroutine locked to an OS thread that lives for the whole run. This covers the container and the listener, but not the run directory.
- **Sweep at the next start.** Label each Operator Verifier container, and record `approve`'s PID in the run directory. At start, `approve` removes labelled containers and run directories whose owning process is gone. This catches what the first option can't, the directory and a killed engine, but only once the operator runs `approve` again.
- **Tell operators.** The Unlock Ceremony runbook gets a line for a crashed `approve`: how to list and remove the container and the directory.

The first two options together close the gap. The third is cheap and helps with what's already out there.

**Blocked by:** none

**Status:** ready-for-agent

**Spec:** §0 requirement 3, §10 AT-18; [EV-12](../evals/12-approve-killed.md).

- [ ] After a SIGKILL to `approve`, no Operator Verifier container or listener remains within a few seconds.
- [ ] The next `approve` removes an earlier run's directory and container before it starts its own.
- [ ] EV-12 passes (`test/e2e/evals-cluster.sh ev12`).
- [ ] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments

- EV-12 on the scratch VM (kind + Kata 4.2.0 + swtpm, rootless podman for the Operator Verifier) found, after the SIGKILL and again after a second `approve`: a listener on `127.0.0.1:46665`; the run directory `/run/user/1000/trustee-bootstrap-verifier-1813350249`, with the Share payload; and the KBS container `5afefdaacda8`. The eval removed them afterwards.
