# 15: cococtl mount

**What to build:** a Security Operator runs the same commands as `cococtl trustee-bootstrap …` and `kubectl coco trustee-bootstrap …`. The `cococtl` change, delivered as a fork or PR, mounts this repo's exported command tree in about five lines. Existing commands gain no new startup dependency.

**Blocked by:** 03

**Status:** done

**Spec:** §6; ADR 0001.

- [x] `cococtl`'s existing tests pass unchanged (AT-01).
- [x] `cococtl trustee-bootstrap status` works against the ticket 03 test setup.

## Comments

### What landed

- **The cococtl patch:** `docs/cococtl/0001-Mount-the-trustee-bootstrap-command-tree.patch`, for cococtl `v0.18.0` (`7c05ec25`, also `main` on 2026-11-11). Four lines in `cmd/root.go` plus `go.mod`/`go.sum`. `docs/cococtl/README.md` says how to apply and test it, and lists the before/after results. Nothing went to GitHub: the user opens the fork or PR.
- **Module version:** trustee-bootstrap has no published version, so the patch carries `replace ... => ../trustee-bootstrap`. The upstream PR needs a tagged release and `go get ...@<tag>` in its place.
- **`pkg/cli` change:** `defaultEnv()` used to call `verifier.DefaultEngine()` (`exec.LookPath("podman")`) when the tree was built. cococtl builds the tree in `init()` for every command, so every cococtl run would have searched `PATH`. The lookup now runs when `approve` starts the Operator Verifier. `pkg/cli` sets no global flags and never calls `os.Exit`.

### AT-01

Ran on the scratch VM against `v0.18.0` with and without the patch: `make vet`, `make build`, `make test` exit 0 with the same test list; `go test ./...` gives the same package results; `TestEvalOffline` (with `COCOCTL_BINARY`) passes 19 of 19; golangci-lint 2.12.2 with cococtl's config reports 0 issues. `go test ./eval/...` fails both ways at `v0.18.0`: it wants a `kubectl-coco` binary that `make build` does not make.

Startup, compared locally with `strace -f -e trace=%file,%network,%process` on `cococtl initdata --help`: no new network, exec or PATH syscalls, and the same output. **One new file read remains: `/etc/localtime`.** `github.com/BurntSushi/toml/internal` calls `time.Now().Zone()` in a package variable. It cannot fail a command (Go falls back to UTC). Removing it means swapping the TOML parser that the sealed-config checks use, which is a decision for the user, not this ticket. New `init` work is about 0.2 ms, all in memory. The binary grows 1.1 MB.

`go mod tidy` raises some of cococtl's dependencies: `go` 1.25.0 to 1.25.3, cobra v1.10.1 to v1.10.2, and indirect modules shared with client-go (`golang.org/x/net` v0.47.0 to v0.57.0, protobuf, go-openapi, easyjson). MVS reads all of vault's `go.mod`, though only `shamir` gets compiled.

### status on the VM

`~/t15/vm-run.sh` (copy in the session scratchpad): split 2-of-3, seal a minimal tree, run `cmd/bootstrap-helper` on `127.0.0.1:18090`, then call `status` three ways. `trustee-bootstrap status`, `cococtl trustee-bootstrap status` and `kubectl coco trustee-bootstrap status` (kubectl v1.35.0, `kubectl-coco` on `PATH`) printed the same JSON: `state: COLLECTING`, `threshold: 2`, the ceremony's `key_id`. A refused connection exits 1. Output in `~/t15/out`.

### Gate

the Go gate against `trustee-bootstrap`: PASS (golangci-lint 0 issues, gremlins 0 mutants in the changed lines, jscpd no new clones). No unit test covers the lazy lookup: nothing in the process can observe a `PATH` search. The strace comparison is the check.
