# EV-07: Seal with a public or CA certificate

**Category:** operator mistake
**Runs on:** a sealing machine with the release binaries and `openssl`
**Covers:** condition 6; residual risk "`kbs_cert` adds a root"; [seal.md](../runbooks/seal.md) step 3 and its witness check; spec §1

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

For each variant, someone stops the bundle before step 9 publishes its digest: either `seal` refuses, or the witness flags the certificate and the Infrastructure Operator starts again from step 1.

## Notes

`pkg/seal` reads no certificate today, so only the witness stands between a public name and the cluster. If the witness misses a variant, the eval fails. The fix to weigh is a fourth sealed-config check that reads the certificate KBS serves, which would change spec §3.

The `ca` variant fails late without a check: rustls in the guest refuses a CA certificate as a server certificate, so workloads can't connect after an unlock that cost K Security Operators.

## Results

None yet.
