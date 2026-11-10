# 07 Go module, command tree and ceremony formats

Status: open
Type: task
Blocked by: none

## What

Create the Go module and the first package. This ticket needs no VM, so it can start alongside the spikes.

- `go.mod`, `cmd/trustee-bootstrap/` (standalone CLI main) and `pkg/cli/` exporting `NewTrusteeBootstrapCmd()` (Cobra).
- `pkg/ceremony/`: the Ceremony Manifest type and validator, Share files, split and combine with `github.com/hashicorp/vault/shamir`, and Share Commitments.
- The `ceremony split --threshold K --holders a,b,c` command: generate an age identity, split it, write the Share files and `ceremony.json`, never write the identity to disk.

## Spec

`IMPLEMENTATION_SPEC.md` §3 items 1-3, §5 (manifest validation), §6, §8; ADR 0001, 0003, 0006.

## Done when

- [ ] Manifest validation rejects repeated indices or commitments, `threshold < 2`, and `threshold > len(shares)`.
- [ ] A 2-of-3 split round-trips; any 2 Shares reconstruct the identity, 1 doesn't.
- [ ] Each Share's hash matches its commitment in the manifest.
- [ ] Unit tests cover every rejection; the Go gate exits 0.
