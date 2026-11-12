# Evals

Each eval names a situation that a deployed trustee-bootstrap must survive: a hostile host, an operator mistake, an upgrade, a roster change or a partial failure. It gives the setup, the action and the expected outcome. A person or an agent runs it, and the result is pass or fail.

The evals sit above acceptance tests AT-01 to AT-28 ([`IMPLEMENTATION_SPEC.md`](../../IMPLEMENTATION_SPEC.md) §10). An AT checks one mechanism. An eval checks that the claims in [`SECURITY_THREAT_MODEL.md`](../../SECURITY_THREAT_MODEL.md) still hold while people follow the [runbooks](../runbooks/) and the host fights back. Each eval fills a gap in the [coverage map](#coverage-map).

A cluster that refuses everything passes every negative eval. The healthy-path evals, EV-16 to EV-19, catch that. They walk one working unlock from deploy to a workload holding its key, and list what the cluster and the CLI print at each step. Compare against them when a real unlock looks wrong.

## Status

| # | Eval | Category | Runs on | Last result |
|---|---|---|---|---|
| EV-01 | [Host swaps the Sealed Bundle in a live pod](01-host-swaps-bundle-in-pod.md) | hostile host | `evals.sh` | pass, 2026-11-12 |
| EV-02 | [Host splices one approval into several CVMs](02-host-splices-one-approval.md) | hostile host | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-03 | [Host ignores a withdrawal](03-host-ignores-a-withdrawal.md) | hostile host | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-04 | [Impostor Trustee serves workloads](04-impostor-trustee.md) | hostile host | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-05 | [Security Operator reviews a weakened Init-Data](05-weakened-init-data-review.md) | operator mistake | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-06 | [Runbook error paths match the CLI](06-runbook-error-paths.md) | operator mistake | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-07 | [Seal with a public or CA certificate](07-seal-with-public-certificate.md) | operator mistake | `evals-offline.sh` | pass, 2026-11-12 |
| EV-08 | [Ceremonies leave no secret on disk](08-ceremonies-leave-no-secret.md) | operator mistake | `evals-offline.sh` | pass, 2026-11-12 |
| EV-09 | [Upgrade the Bootstrap Helper and roll back](09-helper-upgrade-and-rollback.md) | upgrade | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-10 | [Roster change locks out a departed operator](10-roster-change.md) | roster change | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-11 | [Pod recreation after unlock forgets everything](11-pod-recreation-after-unlock.md) | partial failure | `evals.sh` | pass, 2026-11-12 |
| EV-12 | [`approve` killed with SIGKILL](12-approve-killed.md) | partial failure | `evals-cluster.sh` | fail (ticket 20), 2026-11-12 |
| EV-13 | [Relay cut after release](13-relay-cut-after-release.md) | partial failure | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-14 | [Broken sealed resource policy](14-broken-sealed-policy.md) | partial failure | `evals-cluster.sh` | pass, 2026-11-12 |
| EV-15 | [Canary sweep after a full unlock](15-canary-sweep.md) | secret hygiene | `evals.sh` | pass, 2026-11-12 |
| EV-16 | [Deployed Trustee CVM waits for Shares](16-healthy-before-unlock.md) | healthy path | `golden-path.sh` | pass, 2026-11-12 |
| EV-17 | [Two Security Operators unlock Trustee](17-healthy-unlock.md) | healthy path | `golden-path.sh` | pass, 2026-11-12 |
| EV-18 | [A CoCo workload gets a key from the unlocked Trustee](18-healthy-workload-gets-key.md) | healthy path | `golden-path.sh` | pass, 2026-11-12 |
| EV-19 | [Trustee container restarts inside the running CVM](19-healthy-trustee-restart.md) | healthy path | `golden-path.sh` | pass, 2026-11-12 |

**Runs on:**

- **kind + swtpm:** the cluster from `test/e2e/kind-kata-swtpm.sh up`, on the scratch VM or in CI.
- **go test:** an in-process test with `internal/trusteetest` and `internal/memnet`.
- **genpolicy only, sealing machine, scratch VM, operator workstation:** a machine with the release binaries and the tools the runbook names, and no cluster.

None of these is a real TEE. [Ticket 17](../tickets/17-real-tee-release-gate.md) owns AT-16 and the go/no-go. Rerun EV-15 there: on a real TEE it also covers guest memory.

## Running an eval

1. Read the eval and every document on its **Covers** line.
2. Build the setup. An eval that walks a runbook expects you to run the runbook's commands as written, typos and all, before you adapt anything.
3. Check every bullet under **Expected**. The eval passes only when all of them hold.
4. Append a dated entry under the eval's `## Results`: the commit, where it ran, pass or fail, and the evidence (a log path or the command output). Update **Last result** above.
5. Open a ticket in [`docs/tickets/`](../tickets/README.md) for each failure, and link it from the result.

When an eval gets a script, put it in `test/e2e/` or a Go test, and name the path on the eval's **Runs on** line.

### The healthy path, scripted

`test/e2e/golden-path.sh` runs EV-16 to EV-19 on the cluster that `test/e2e/kind-kata-swtpm.sh up` builds. It writes the transcript to stdout, checks every bullet under **Expected**, and prints `PASS` and exits 0 only when all four evals pass:

```sh
export E2E_ENGINE=podman
test/e2e/kind-kata-swtpm.sh up         # once; about 25 min cold, 6 min warm
test/e2e/golden-path.sh >transcript.txt
```

### Scripted negative evals

`test/e2e/evals.sh` runs EV-01, EV-11 and EV-15 on the same cluster, after one shared setup. The sealed resource is a random canary, which EV-15 then searches for. Name evals to run fewer of them:

```sh
test/e2e/evals.sh              # EV-01, EV-11 and EV-15
test/e2e/evals.sh ev01 ev15
```

It prints `PASS` and exits 0 only when every eval it ran passes.

`test/e2e/evals-offline.sh` runs the evals that need no cluster, EV-07 and EV-08. It needs Go, `openssl`, `jq` and passwordless `sudo`. EV-08 mounts tmpfs at `/mnt/ceremony` and `/mnt/seal` and searches the whole root file system, so run it on a scratch machine:

```sh
test/e2e/evals-offline.sh              # EV-07 and EV-08
test/e2e/evals-offline.sh ev07
```

`test/e2e/evals-cluster.sh` runs the other cluster evals, EV-02 to EV-06, EV-09, EV-10 and EV-12 to EV-14, after one shared setup. Each eval runs in its own subshell, so one failure doesn't stop the rest, and the summary names every eval that failed. EV-12 fails today, on ticket 20.

```sh
test/e2e/evals-cluster.sh              # all ten
test/e2e/evals-cluster.sh ev04 ev13
```

### Walking the evals yourself

To check each step by hand, with a human in the loop, stop where EV-16 starts:

```sh
E2E_WORK=~/ev/hil test/e2e/golden-path.sh hil
source ~/ev/hil/hil.env
```

The Trustee CVM now waits for Shares. Type the commands from EV-16 to EV-19 and compare what you see with each eval's **Expected**. In that shell:

- `kubectl` and `crictl` run inside the kind node, so pass a manifest on stdin: `kubectl apply -f - <workload-ok.yaml`.
- Each Security Operator's files sit in the work directory: `--policy policy-alice --share-file ceremony/alice.share`, and the same for `carol`.
- `node <command>` runs a command on the kind node, for example the `ls` of the state volume in EV-17.

## Coverage map

Each claim, invariant and residual risk in `SECURITY_THREAT_MODEL.md`, the tests that cover it today, and the eval that fills the gap. A row with no gap has no eval.

### Invariants

| # | Invariant | Covered today | Gap | Eval |
|---|---|---|---|---|
| 1 | No Share before attestation | AT-03, AT-04, AT-28 (e2e) | A host that controls the relay can route one run's inner connections to several CVMs | EV-02 |
| 2 | No key substitution | AT-05 (e2e, attacker `tee-pubkey`, `replay`) | | |
| 3 | Only genuine Shares | AT-07, AT-08 (`pkg/helper`) | A departed operator's old Share, at pod level | EV-10 |
| 4 | Only the Approved Bundle | AT-09, AT-10, AT-23 (`pkg/helper`, `cmd/bootstrap-helper` only) | No pod-level run | EV-01, EV-09 |
| 5 | Measured manifest | AT-11 (e2e `check_swapped_manifest`) | | |
| 6 | No host plaintext | AT-16 (real TEE only); e2e `check_host_view` sees an empty state volume | Logs, events, objects, node files, operator workstation | EV-12, EV-15 |
| 7 | No partial start | AT-14, AT-26 | A published tree that Trustee can't load | EV-14 |
| 8 | Fresh boot, fresh ceremony | AT-15 (helper restart), AT-26 (container restart) | Pod recreation, eviction and node reboot after unlock | EV-11 |
| 9 | Identity follows approval | AT-17 (the real Trustee only) | An impostor KBS behind Trustee's Service | EV-04 |
| 10 | Only genuine tokens | AT-21 (e2e) | | |

### Residual risks

| Residual risk | Covered today | Gap | Eval |
|---|---|---|---|
| Init-Data is the single root | The review checklist in the Unlock Ceremony runbook | Nobody has tested the checklist against a weakened Init-Data | EV-05 |
| Agent policy lets the host drop pinned values | AT-11, `cmd/bootstrap-helper` tests, e2e `check_tampered` | | |
| Plain HTTP relay | AT-06 | Accepted metadata exposure | |
| `kbs_cert` adds a root | Sealed-config check 4 in `seal` and the helper (ticket 18, AT-27); the seal runbook's witness check | | EV-04, EV-07 |
| Upstream sample configs are unsafe | AT-21, AT-22, AT-27 | | |
| The Infrastructure Operator sees the plaintext | The seal runbook only | Nobody has checked the runbook for leaks | EV-08 |
| Claim profiles cover only what was tested | `policy build` refuses untested profiles (ticket 14) | Real-TEE run | ticket 17 |
| Released Shares are irrevocable for a live boot | Withdraw runbook, walked with an honest host (ticket 16) | A host that ignores the withdrawal | EV-03 |
| An approval covers a configuration, not one VM | Documented 2026-11-12; nothing limits the count | Up to 4 CVMs per `approve` run, untested | EV-02 |
| Availability | ADR 0002 | Pod recreation after unlock | EV-11 |
| Roster change | Runbook, never walked as a whole (ticket 16) | The whole runbook, and a departed operator | EV-10 |
| TPM/swtpm gives no confidentiality | `policy build` flag (ticket 14) | | |

### Procedures and open items

| Item | Covered today | Gap | Eval |
|---|---|---|---|
| Trustee upgrade runbook | Never walked as a whole (ticket 16) | The whole runbook, rollback, and a stale genpolicy | EV-09 |
| Runbook error messages | None | The runbooks quote CLI errors that code changes can break | EV-06 |
| Key Ceremony and seal runbooks | Walked (ticket 16) | Nobody checked the disk afterwards | EV-08 |
| AT-18 cleanup | SIGINT, SIGTERM, success, failure | SIGKILL | EV-12 |
| A relay that drops mid-release | AT-07 in `pkg/helper` | The operator's retry, at pod level | EV-13 |
| Spec §9: a broken sealed policy in the Trustee CVM | Ticket 14, KBS outside a CVM | Inside the Trustee CVM | EV-14 |
