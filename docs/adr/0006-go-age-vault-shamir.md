# Go, age and Vault's Shamir, not Rust

The Bootstrap Helper and all tooling are written in Go. Sealing uses `filippo.io/age` (X25519 recipients), and Shamir splitting uses `github.com/hashicorp/vault/shamir`, which Vault uses for its own unseal. The pre-baseline draft spec preferred Rust because CoCo's guest components are Rust. The Bootstrap Helper, however, never links them: it reaches attestation through the CDH's HTTP API.

A single Go module therefore owns the manifest, share and seal formats for both the Bootstrap Helper and the `cococtl` command, so the formats cannot drift between two language implementations. The Infrastructure Operator can also seal with the stock `age` CLI.

## Considered Options

- Rust with `age`/rage plus a Rust Shamir crate: rejected because the Rust Shamir crates are less established, and `cococtl` would need a second, Go implementation of every format.
