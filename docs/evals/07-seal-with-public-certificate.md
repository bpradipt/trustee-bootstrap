# EV-07: Seal with a public or CA certificate

**Category:** operator mistake
**Runs on:** a sealing machine with the release binaries and `openssl`
**Covers:** condition 6; residual risk "`kbs_cert` adds a root"; [seal.md](../runbooks/seal.md) step 3 and its witness check; spec §1 and §3 sealed-config check 4; [ticket 18](../tickets/18-check-trustee-tls-certificate.md)

## Setup

The seal runbook's preconditions, and three trees that differ only in `tls.crt`:

| Variant | Certificate |
|---|---|
| public-name | SAN `DNS:trustee.example.com`, a name a public CA would certify |
| public-ip | SAN `IP:` a public address |
| ca | `basicConstraints=critical,CA:TRUE` |

## Action

The Infrastructure Operator walks seal.md steps 3 to 9 with each variant. A witness who doesn't know the variant runs the step 3 check.

## Expected

- At step 6, `seal` refuses each variant, names the failed check (`names a host outside the cluster` or `is a CA certificate`), and writes no bundle.
- The witness's step 3 check flags each variant as well, one step earlier.
- AT-27 shows the helper refusing the same tree sealed with stock `age`.

## Notes

Ticket 18 added sealed-config check 4 after this eval found that only the witness checked the certificate. Without that check, the `ca` variant fails late: rustls in the guest refuses a CA certificate as a server certificate, so workloads can't connect after an unlock that cost K Security Operators.

## Results

- 2026-11-12, ticket 18 on top of `evals` at `5a7e7cb`, scratch VM: **pass** for `seal`. It sealed a control tree with a leaf for `trustee.default.svc.cluster.local`. It refused `DNS:trustee.example.com` and `IP:8.8.8.8` with `names a host outside the cluster`, and `CA:TRUE` with `is a CA certificate`, and wrote no bundle for any of the three. AT-27 in `go test` covers the helper. Nobody walked the witness step for this run.
