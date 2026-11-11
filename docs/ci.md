# CI

`.github/workflows/ci.yml` runs on every pull request and on each push to `main`. It has two jobs. Each job calls `test/e2e/ci.sh`, so you can run the same steps on your machine.

| Job | Runs | Locally |
|---|---|---|
| `go` | `go vet`, `go test`, and the Go gate's checks on the changes since the base commit | `test/e2e/ci.sh go`, then `test/e2e/ci.sh lint <base>` |
| `e2e` | the claim-profile fixtures through the pinned KBS image (AT-28), then `kind-kata-swtpm.sh up`, `share-release.sh`, `trustee-cvm.sh` and `down` | `test/e2e/ci.sh e2e` |

## The Go gate in CI

`ci.sh lint` runs its three Go tools with its limits and arguments:

- golangci-lint 2.12.2 with `.golangci.yml`: gocognit 15, cyclop 10, funlen 60 lines and 40 statements, on every function in each changed file.
- gremlins 0.6.0 on the changed lines. A `LIVED` or `NOT COVERED` mutant fails the job.
- jscpd 5.4.2 on the Go code outside tests. A clone that the base commit lacks fails the job.

`ci.sh` downloads each tool from its public release and checks it against the sha256 pinned in `ci.sh`. When a pinned tool or a limit changes, update `ci.sh` and `.golangci.yml` together.

Before each commit that touches Go, run `test/e2e/ci.sh lint <base>` yourself.

## Required checks

A workflow file can't block a merge. A repository admin must turn on branch protection for `main` (Settings, Branches) and add `go` and `e2e` as required status checks. Without that setting, a red run is only a warning.

## Runner and cache

- **Runner.** The `e2e` job needs `/dev/kvm`. GitHub-hosted `ubuntu-24.04` runners have it, and the job opens it to the runner user with a udev rule. A self-hosted runner needs nested virtualization, rootful podman, `sudo`, `apt-get`, network access and about 8 GB of free disk.
- **Cache.** A cold `e2e` run spends about 20 minutes on the guest kernel and the Attestation Agent. The job caches `~/.cache/trustee-bootstrap-e2e/out`, keyed on the scripts that hold the pins. A changed pin builds again from scratch.

## Adding a test

A later ticket adds its acceptance test to `test/e2e/ci.sh`, or as a Go test that `go test ./...` runs. The workflow needs no change.
