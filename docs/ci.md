# CI

`.github/workflows/ci.yml` runs on every pull request and on each push to `main`. It has two jobs. Each job calls `test/e2e/ci.sh`, so you can run the same steps on your machine.

| Job | Runs | Locally |
|---|---|---|
| `go` | the module pin checks, `go vet`, `go test`, the Go gate's checks on the changes since the base commit, and the release build with its SBOMs | `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>`, then `test/e2e/ci.sh release DIR` |
| `e2e` | the claim-profile fixtures through the pinned KBS image (AT-28), then `kind-kata-swtpm.sh up`, `share-release.sh`, `trustee-cvm.sh` and `down` | `test/e2e/ci.sh e2e` |

## The Go gate in CI

`ci.sh lint` runs its three Go tools with its limits and arguments:

- golangci-lint 2.12.2 with `.golangci.yml`: gocognit 15, cyclop 10, funlen 60 lines and 40 statements, on every function in each changed file.
- gremlins 0.6.0 on the changed lines. A `LIVED` or `NOT COVERED` mutant fails the job.
- jscpd 5.4.2 on the Go code outside tests. A clone that the base commit lacks fails the job.

`ci.sh` downloads each tool from its public release and checks it against the sha256 pinned in `ci.sh`. When a pinned tool or a limit changes, update `ci.sh` and `.golangci.yml` together.

Before each commit that touches Go, run `test/e2e/ci.sh lint <base>` yourself.

## Release build and SBOM

`ci.sh release DIR [VERSION]` builds `trustee-bootstrap` and `bootstrap-helper` with the flags the helper image uses (`CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w -buildid='`). For each binary it writes a CycloneDX SBOM, `<binary>.cdx.json`, then `SHA256SUMS` over all four files. VERSION defaults to `git describe --tags --always --dirty`.

The SBOM tool is cyclonedx-gomod v1.12.0, run with `go run module@version`. The Go checksum database verifies that version's source and its dependencies, so the tool needs no separate sha256. Its `bin` mode reads the module list that the Go linker embeds in each binary, so the SBOM lists exactly the modules that binary links. The `go` job runs the release build and uploads `DIR` as the `release` artifact.

## Pins and test code

- `ci.sh go` runs `go mod tidy -diff` and `go mod verify` first. They fail if `go.mod` or `go.sum` is stale, or if a downloaded module differs from its `go.sum` hash.
- `test/supplychain` runs under `go test ./...`. It fails if a container image in the code, scripts or manifests lacks an `@sha256:` digest, if a workflow action is not pinned by commit SHA, if either release binary links `testing`, `net/http/httptest`, `internal/memnet`, `internal/trusteetest` or anything under `test/`, or if a non-test `.go` file appears under `test/`.

## Required checks

A workflow file can't block a merge. A repository admin must turn on branch protection for `main` (Settings, Branches) and add `go` and `e2e` as required status checks. Without that setting, a red run is only a warning.

## Runner and cache

- **Runner.** The `e2e` job needs `/dev/kvm`. GitHub-hosted `ubuntu-24.04` runners have it, and the job opens it to the runner user with a udev rule. A self-hosted runner needs nested virtualization, rootful podman, `sudo`, `apt-get`, network access and about 8 GB of free disk.
- **Cache.** A cold `e2e` run spends about 20 minutes on the guest kernel and the Attestation Agent. The job caches `~/.cache/trustee-bootstrap-e2e/out`, keyed on the scripts that hold the pins. A changed pin builds again from scratch.

## Adding a test

A later ticket adds its acceptance test to `test/e2e/ci.sh`, or as a Go test that `go test ./...` runs. The workflow needs no change.
