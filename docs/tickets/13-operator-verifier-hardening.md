# 13: Operator Verifier hardening

**What to build:** neither verifier releases anything to a forged token or an unauthenticated admin call, and `approve` leaves nothing behind. The Operator Verifier listens only on `127.0.0.1`. It refuses to start with insecure token or admin settings. Its tmpfs directory, container and listener disappear on success, failure and signals. The unlocked Trustee resists the same attacks.

**Blocked by:** 05

**Status:** done

**Spec:** §4 step 2, §6; threat model rows for forged tokens and admin calls.

- [x] AT-02 and AT-18 pass.
- [x] A malicious relay that replays old evidence or substitutes its own `tee-pubkey` gets no release (AT-05).
- [x] AT-21 and AT-22 pass against both the Operator Verifier and the unlocked Trustee (the latter once ticket 06 is done).
- [x] the Go gate exits 0.

## Comments

### What landed

- **`approve` handles SIGINT and SIGTERM.** It wraps its context in `signal.NotifyContext`. A signal cancels the context, the engine gets SIGTERM, the container stops, and the deferred stop deletes the run directory. Before this change a signal killed the CLI outright: the run directory stayed, and a `kill` that reached only the CLI left the container running. `TestApproveStopsTheOperatorVerifierOnSignal` sends each signal to the test process. Without the handler the signal kills the test.
- **The run directory must be on tmpfs.** `Runtime.Start` runs `statfs` on `$XDG_RUNTIME_DIR` (or `/dev/shm`) and refuses anything but `TMPFS_MAGIC`, before it reserves a port or writes a file.
- **Loopback only.** `Runtime.Start` refuses any reserved address whose host is not `127.0.0.1` (AT-02 as a code check, not only the constant in `approve`).
- **Rootful engines.** On the VM, the pinned KBS writes the AS default policies into `storage/attestation_service_policy`. A rootful engine (simulated with `sudo podman`) creates that directory as root, and the operator can't delete it, so the run directory survived `stop`. A rootless run deletes cleanly. `writeRunDir` now creates the directory first, so it stays the operator's. Root-owned files inside a user-owned directory can be unlinked. The probe ran before this fix. The fixed path has not run (see below).
- **Bounded KBS output.** The in-memory buffer keeps the last 64 KiB, the end of the log, where a failing KBS says why.
- **`test/e2e/attacker`**: test-only Go (a `_test.go` package, so it never ships and gremlins never mutates it). The scripts build it with `go test -c` and pick the attack with `-attack`. Under `go test ./...` it skips. Through a relay, it poses as the Bootstrap Helper and passes the real helper's status through:
  - `forge`: an ES256 token whose header carries the attacker's key (`jwk` plus a self-signed `x5c`), with the claims the target's resource policy wants and the attacker's TEE key at the EAR `tee-pubkey` path. By the v0.22.0 source (`kbs/src/crypto/jwt.rs`), KBS with `insecure_header_jwk = true` uses that key as is. With `false`, the `x5c` must chain to a trusted cert, and it does not.
  - `admin`: `POST /kbs/v0/resource-policy` with an allow-all policy, once with no token and once with an Ed25519 admin token the attacker signed. Then it checks that the running Operator Verifier's `resource-policy.rego` still equals the operator's.
  - `hold`: keeps the relay open and sends nothing, so the scripts can signal a running `approve`.
  - `pass` / `tee-pubkey` / `replay`: a man in the middle at the HTTP level between the real helper's relay and `approve`'s relay. `pass` re-encodes the attestation request unchanged and records it. It must get a release, which proves the attack path works. `tee-pubkey` swaps in the attacker's TEE key. `replay` sends the recorded request with this session's nonce, so only the evidence binding can catch it. Both fail when any `/kbs/v0/resource/` answer is 200 or when they saw no attestation request.
  - Directly (`-kbs URL`): `forge` and `admin` against the unlocked Trustee.
- **e2e wiring** (`ci.sh e2e` already runs both scripts):
  - `share-release.sh`: `assert_clean` (no KBS container in the CLI's or the rootful engine, no `trustee-bootstrap-verifier-*` run directory, listeners equal to the baseline) after every `approve`. `signal_approve INT|TERM` checks AT-02 while `approve` holds a relay open to `hold`, then AT-18. `relay_attacks` runs `forge`, `admin` (with a `sudo podman` shim as a rootful engine), the `pass` control, `tee-pubkey` and `replay`.
  - `trustee-cvm.sh`: `check_host_attacks` copies the attacker into the kind node and runs `forge` and `admin` against the `trustee` ClusterIP. `check_workloads` runs after it, so an allow-all policy would show up as the unauthorized workload getting the secret.

### Run on the scratch VM

```sh
vmsync <worktree> t13/repo
vmssh 'cd ~/t13 && PATH=$HOME/sdk/go/bin:$PATH E2E_CACHE=~/t07/cache/e2e ./repo/test/e2e/ci.sh e2e'
```

Run 4 exited 0 end to end. Log: `~/t13/e2e.log` on the VM, with runs 1 to 3 in `e2e-run{1,2,3}.log`.

- **share-release.sh:**
  - AT-02: while `approve` held a relay open, its only new listener was `127.0.0.1:<port>`.
  - AT-18: nothing remained after SIGINT, after SIGTERM, with a rootful engine (`sudo podman`), after both accepted Shares (image and `--kbs-binary`) and after the AT-04 denial.
  - AT-21 and AT-22 held against the Operator Verifier.
  - AT-05: the untouched pass-through gave alice's Share to the genuine CVM. Then the swapped `tee-pubkey` and the replay each got "not accepted", and the status stayed `COLLECTING [1]`.
- **trustee-cvm.sh:**
  - AT-21 and AT-22 were refused by the unlocked Trustee, reached from the kind node at the `trustee` ClusterIP.
  - AT-24, which runs right after, still showed the sealed policy in force.
  - Every earlier check (AT-13, 25, 17, 26, 11, the agent policy, tmpfs) passed too.

- **AT-21 and AT-22 on the Operator Verifier.** The forged token got `401 TokenVerifierError`. Both policy replacements got `401 AdminAuthAccess`: "Failed to parse HTTP Auth Bearer header" without a token, and "Cannot verify token with any of the issuers" with the attacker's token.
- **Positive control for `forge`, run by hand** (`~/t13/probe/control.sh`): copy a live run directory, set `insecure_header_jwk = true` and run the pinned KBS on it. The same forged token got `HTTP 200` and a JWE for the attacker's TEE key. So the 401 comes from the setting, not from a malformed token.
- **Fixes the runs needed.** Run 1 failed at `AT-18 (SIGINT): listeners changed`. The missing listener was the attacker's own, which had exited after the baseline. `listeners()` now leaves it out. Run 2 passed every check in share-release.sh and every ticket 13 check in trustee-cvm.sh. It then failed in ticket 09's `check_swapped_manifest` on `pods "trustee-cvm" not found`. `check_tampered` had started that delete with `--wait=false`, and this time the pod was gone first. Both `kc delete pod "$POD" --wait` calls now pass `--ignore-not-found`. Run 3 passed every ticket 13 check. It then failed ticket 11's AT-26 check: after `crictl stop`, the Trustee container went into back-off. The Kata agent had already timed out a create call in that run (`ttrpc ... Receive packet timeout`), so the guest looks overloaded. AT-26 passed in runs 2 and 4 with the same code, so this run 3 failure is an intermittent ticket 11 problem, not a ticket 13 one. It is worth watching in CI.
- **Before access dropped, the run-directory probe on the VM** showed that a rootful engine left `storage/attestation_service_policy` root-owned and the run directory behind. A rootless engine did not.

- **Gate:** the Go gate against `trustee-bootstrap` PASS (golangci 0 issues, gremlins 7 killed / 0 lived / 0 not covered, jscpd no new clones). `go vet ./...` and `go test ./...` pass locally.
