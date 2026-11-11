# cococtl mount

`0001-Mount-the-trustee-bootstrap-command-tree.patch` adds this repo's command tree to
[cococtl](https://github.com/confidential-devhub/cococtl) as `cococtl trustee-bootstrap`. The kubectl
plugin gets it too, as `kubectl coco trustee-bootstrap` (ADR 0001, spec §6).

It applies to cococtl `v0.18.0`, commit `7c05ec25d7e5eeec0f80c43896d83dbe937af8d1` (that tag was
also `main` on 2026-11-11). The code change is four lines in `cmd/root.go`: an import, a two-line comment and
`rootCmd.AddCommand(trusteebootstrap.NewTrusteeBootstrapCmd())`. The rest of the patch is `go.mod`
and `go.sum`.

## Apply and test

trustee-bootstrap has no published module version yet. The patch therefore carries
`replace github.com/confidential-devhub/trustee-bootstrap => ../trustee-bootstrap`, so put both
checkouts side by side:

```sh
git clone https://github.com/confidential-devhub/cococtl
git -C cococtl checkout -b trustee-bootstrap v0.18.0
git -C cococtl am ../trustee-bootstrap/docs/cococtl/0001-Mount-the-trustee-bootstrap-command-tree.patch
cd cococtl
make vet build test
COCOCTL_BINARY=$PWD/cococtl go test -run TestEvalOffline ./eval/...
./cococtl trustee-bootstrap status --endpoint http://<helper>:<port>
```

`go test ./eval/...` without `COCOCTL_BINARY` fails at `v0.18.0` with or without the patch: it looks
for a `kubectl-coco` binary that `make build` does not create.

## Before you open the upstream PR

1. Tag a trustee-bootstrap release.
2. In cococtl, drop the `replace` line and run
   `go get github.com/confidential-devhub/trustee-bootstrap@<tag> && go mod tidy`.

`go mod tidy` also raises some of cococtl's existing dependencies. The patch moves `go` from 1.25.0 to
1.25.3 and cobra from v1.10.1 to v1.10.2. MVS reads the whole `github.com/hashicorp/vault` `go.mod`,
even though trustee-bootstrap only uses its `shamir` package (ADR 0006). That raises indirect
versions that cococtl shares with client-go: `golang.org/x/net` (v0.47.0 to v0.57.0),
`google.golang.org/protobuf`, `go-openapi/swag`, `mailru/easyjson`. cococtl's own tests pass with
these versions (below).

## What was checked (ticket 15)

Ran on the scratch VM (Go 1.26.4), against cococtl `v0.18.0` with and without the patch:

| Check | Without | With |
|---|---|---|
| `make vet`, `make build`, `make test` | exit 0 | exit 0, same test list and results |
| `go test ./...` package results | same (only `eval` fails, see above) | same |
| `TestEvalOffline` with `COCOCTL_BINARY` | 19 pass | 19 pass |
| `golangci-lint run ./...` (2.12.2, cococtl's `.golangci.yml`) | 0 issues | 0 issues |

Startup, local, `cococtl initdata --help` under `strace -f -e trace=%file,%network,%process`:

- No new network, exec or PATH lookups. The output of `initdata --help` is byte-for-byte the same.
  `cococtl --help` gains one line, for `trustee-bootstrap`.
- One new file read: `/etc/localtime`. `github.com/BurntSushi/toml/internal` calls
  `time.Now().Zone()` in a package variable initializer. Go falls back to UTC when the file is
  missing, so this cannot make a command fail. Removing it means another TOML parser for the
  sealed-config checks, which this ticket does not change.
- Added package `init` work (`GODEBUG=inittrace=1`): about 0.2 ms, all in memory (regexp compile in
  `pkg/policy`, crypto and tar tables).
- The binary grows by 1.1 MB (65.1 MB to 66.1 MB).

`NewTrusteeBootstrapCmd()` looks up nothing at construction. cococtl builds it in `init()` for every
command, so `approve` finds podman or docker on `PATH` only when it starts the Operator Verifier.

`status` against a real Bootstrap Helper (`cmd/bootstrap-helper` on `127.0.0.1:18090`, a 2-of-3
ceremony, a sealed minimal tree) printed the same JSON through all three entry points:
`trustee-bootstrap status`, `cococtl trustee-bootstrap status`, and
`kubectl coco trustee-bootstrap status` (kubectl v1.35.0 with `kubectl-coco` on `PATH`). A refused
connection exits 1 with `Error: get status: ...`.
