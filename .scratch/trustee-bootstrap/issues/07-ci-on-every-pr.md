# 07: CI on every PR

**What to build:** every pull request runs the in-process ceremony from ticket 03 and the swtpm end-to-end ceremony from ticket 06, and blocks merge on failure. Later hardening tickets add their acceptance tests to this pipeline.

**Blocked by:** 06

**Status:** done

**Spec:** §9 Phase 2, §11.

- [ ] A PR runs the Go gate, the Go tests and the swtpm end-to-end test. *(The workflow runs the Go tests, the Go gate's tools with its limits, and the e2e test. It is lint-clean, and its steps pass on the scratch VM. No GitHub run yet: the repo has no remote. See Comments.)*
- [ ] A deliberately broken PR fails CI. *(Locally, each `ci.sh` step exits 1 on a broken tree. A real broken PR is still owed. See Comments.)*

## Comments

### What CI runs

`.github/workflows/ci.yml` runs on `pull_request` and on pushes to `main`. Both jobs call `test/e2e/ci.sh`, so a developer runs the same steps with the same script:

- **`go`:** `ci.sh go` (`go vet ./...`, `go test ./...`), then `ci.sh lint <base>`. The base is the pull request's base commit, or `github.event.before` on a push.
- **`e2e`:** opens `/dev/kvm` with a udev rule, installs `tcpdump`, restores `~/.cache/trustee-bootstrap-e2e/out`, runs `kind-kata-swtpm.sh up`, saves the cache, then runs `ci.sh e2e`: `up` (a no-op by then), `share-release.sh`, `trustee-cvm.sh`, and `down` from an EXIT trap. The job runs `up` before `ci.sh e2e` so that the cache is saved even when a test fails. The cache key hashes `kind-kata-swtpm.sh`, `kernel-tpm.conf` and `trustee-cvm.sh`, the files that hold the build pins. The job sets no `restore-keys`: the scripts skip a build whose output exists, so an older cache would hide a changed pin.

Every action is pinned by full commit SHA: `actions/checkout` v7.0.1, `actions/setup-go` v7.0.0, `actions/cache/{restore,save}` v6.1.0. All three tags are lightweight tags on those commits, and each was released more than three months ago. Branch protection is a repository setting, so `docs/ci.md` tells the admin to require the `go` and `e2e` checks.

### The Go gate in CI

`ci.sh lint <base>` downloads golangci-lint 2.12.2, gremlins 0.6.0 and jscpd 5.4.2 from their public release URLs and checks each against the sha256 that the Go gate embeds (its `tools.yaml`). The tools run with the arguments the Go gate passes. I took those from an `strace` of the Go gate on the VM:

- `golangci-lint run -c .golangci.yml --new-from-rev=<merge-base> --whole-files ./...`. `.golangci.yml` is a copy of the config that the Go gate writes and passes with `-c`: gocognit 15, cyclop 10, funlen 60 lines and 40 statements, test files excluded.
- `gremlins unleash --diff <merge-base> --workers 3 --timeout-coefficient 20`, only when a non-test `.go` file changed. A `LIVED` or `NOT COVERED` line fails the step.
- `jscpd --format go --baseline-from-ref <merge-base> --fail-on-new-clones` with the Go gate's ignore list. the Go gate reads the JSON report; `ci.sh` uses `--fail-on-new-clones` and the console reporter.

When a pinned tool or a limit changes, update `ci.sh` and `.golangci.yml` together.

### Proved on the scratch VM (Ubuntu 24.04, podman 4.9.3, 4 vCPU, 6 GB, nested KVM)

The GitHub `ubuntu-24.04` image has the same Ubuntu and podman versions.

- **`actionlint` 1.7.12** (checksum checked), with shellcheck: 0 errors. `shellcheck test/e2e/ci.sh` is clean.
- **`ci.sh go`** on real sockets: vet clean, every package `ok`. No unit test opens a TCP listener, because they all use `internal/memnet`. The e2e scripts run the production listeners: `bootstrap-helper` in the pod and `approve`'s Operator Verifier on `127.0.0.1:0`. That run settles the real-socket run that ticket 03 left to this ticket.
- **`ci.sh lint`**, next to the Go gate on the same tree each time, with an empty tools directory first, so the downloads and checksums ran:

  | Tree | `ci.sh lint` | the Go gate |
  |---|---|---|
  | branch, base `trustee-bootstrap` (no Go change) | 0 | 0 |
  | base `8d62b92` (ticket 06's Go changes) | 0 | 0 |
  | staged untested function | 1, gremlins `NOT COVERED` | 1 |
  | staged function with cognitive complexity 32 | 1, gocognit | 1 |

- **`ci.sh gate`**, the local step, in a fresh `HOME` with the local v0.2.0 binary: the gate's tool install fetched the tools in 6 s. `ci.sh gate trustee-bootstrap` and `ci.sh gate 8d62b92` (ticket 06's Go changes) both print `gate: PASS` and exit 0.
- **e2e**, the job's steps in order, with a fresh `E2E_CACHE` holding only a copy of `out/`, the way a cache restore leaves it: `up` took 53 s (kind downloaded and checked, cluster created). Then `ci.sh e2e` printed `PASS` for share-release (AT-03, AT-06, AT-04) and for trustee-cvm (image, AT-25, AT-13, policy, state, AT-17, AT-24) in 3 min 35 s. `down` ran and no cluster was left.
- **Broken tree.** Each step exited 1:
  - `ci.sh go` with a `t.Fatal` test in `pkg/ceremony`: `FAIL pkg/ceremony`, exit 1.
  - `ci.sh e2e` with `ShareResourcePath` changed to `.../share/other` in `pkg/helper`: `[share-release] FAIL: alice's approve: ... "Share not accepted"`, exit 1. The EXIT trap still ran `down`, and no cluster was left.
  - `ci.sh gate trustee-bootstrap` with an untested exported function staged: `NOT COVERED ARITHMETIC_BASE`, `gate: FAIL`, exit 1.

Repeat (scripts in the session scratchpad, `t07/vm-*.sh`): `vmsync <worktree> t07/repo`, then on the VM `E2E_CACHE=~/t07/cache/e2e test/e2e/ci.sh e2e` with `~/sdk/go/bin` on `PATH`. The gate needs a git clone (vmsync drops `.git`); `t07/gaterepo` comes from a `git bundle` of `trustee-bootstrap`.

### Not done

- **No GitHub run.** The repo has no remote, so no real pull request has run this workflow. These steps stay open until someone pushes the repo and opens two PRs, one clean and one deliberately broken: `/dev/kvm` and rootful podman next to Docker on a hosted runner, the cold 20-minute build within the 90-minute timeout, and the free disk.
- **Branch protection** is a repository setting. `docs/ci.md` says what to require.
- Ticket 04's "CI runner" box stays open for the same reason. The VM is a KVM host, not a CI runner.
