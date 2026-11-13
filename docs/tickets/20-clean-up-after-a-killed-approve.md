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

**Status:** done

**Spec:** §0 requirement 3, §10 AT-18; [EV-12](../evals/12-approve-killed.md).

- [x] After a SIGKILL to `approve`, no Operator Verifier container or listener remains within a few seconds.
- [x] The next `approve` removes an earlier run's directory and container before it starts its own.
- [x] EV-12 passes (`test/e2e/evals-cluster.sh ev12`).
- [x] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments

- EV-12 on the scratch VM (kind + Kata 4.2.0 + swtpm, rootless podman for the Operator Verifier) found, after the SIGKILL and again after a second `approve`: a listener on `127.0.0.1:46665`; the run directory `/run/user/1000/trustee-bootstrap-verifier-1813350249`, with the Share payload; and the KBS container `5afefdaacda8`. The eval removed them afterwards.
- **The first EV-12 evidence was flawed.** The eval started `approve` as `tb approve ... &`, and `tb` is a shell function. Bash runs a backgrounded function in a subshell, so `kill -9 $!` killed that subshell and `approve` kept running. The leftovers it reported belonged to a live `approve`. The gap is still real: with `Pdeathsig` removed, `TestKBSGetsSIGTERMWhenApproveIsKilled` fails, because a KBS whose starter is SIGKILLed keeps running. EV-12 now starts the binary itself, as AT-18's `signal_approve` in `share-release.sh` already did.
- **Built** both options, plus the runbook line:
  - `pkg/verifier` starts the engine, or a native `kbs`, with `Pdeathsig: SIGTERM`. One goroutine, locked to its OS thread, starts it and waits for it, so the thread lives as long as the engine (golang/go#27505).
  - Each run creates its directory under a hidden name, locks it with `flock`, then renames it to `trustee-bootstrap-verifier-*`. The container takes the same name. The kernel drops the lock however the process dies.
  - Before it starts, `Start` sweeps: for each run directory or container with that prefix whose directory no live process holds, it removes the container first, then the directory. It refuses to start if it can't list, check or remove one. `approve` logs a `verifier_swept` warning for each.
  - `approve` now also handles SIGHUP, so a closed terminal runs the normal cleanup.
  - A setuid engine, such as `sudo podman`, clears `Pdeathsig`. Its container then waits for the next sweep. The runbook says so, and tells operators how to clean up by hand.
- **Verified**, 2026-11-13, scratch VM (kind + Kata 4.2.0 + swtpm), branch `approve-cleanup`:
  - `go test -race` passes for `pkg/verifier`, `pkg/cli` and `internal/audit`. The new tests cover the sweep, failures that stop `Start`, a live run left alone, and a SIGKILLed stand-in `approve` whose fake KBS gets SIGTERM. Removing the lock, or `Pdeathsig`, fails the matching test.
  - `test/e2e/ci.sh go` and `test/e2e/ci.sh lint origin/main` exit 0. Gremlins: 23 mutants killed, none lived or uncovered.
  - `test/e2e/share-release.sh` passes. AT-18 holds after SIGINT, SIGTERM, success and failure, and with a rootful engine.
  - `test/e2e/evals-cluster.sh ev12` passes. 5 s after the SIGKILL, only the run directory remained. The second `approve` removed it and logged `verifier_swept`.
  - `test/e2e/golden-path.sh` failed three times on 2026-11-13, each time on the Trustee container's one restart. Each time, the first create failed with the Kata Agent's `ttrpc err: Receive packet timeout`. That create includes the guest's pull of the KBS image, and the VM fetched from ghcr.io at 1.3 MB/s that day (68 MB in 51 s). The default `create_container_timeout` is 60 s.
- **golden-path passes** once the swtpm test config sets `create_container_timeout = 120`, in its own commit on this branch: EV-16 to EV-19, with no Trustee restart. The kubelet caps the timeout at its 2 min `runtime-request-timeout`.
