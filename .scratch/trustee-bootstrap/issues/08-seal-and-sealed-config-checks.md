# 08 Seal, unseal and the sealed-config checks

Status: open
Type: task
Blocked by: 05, 07

## What

`pkg/seal/` and the `seal` command.

- Seal: tar a config directory and age-encrypt it to the manifest's recipient; print the bundle's SHA-256.
- Unseal: decrypt in-memory bytes, extract with the safety rules (no absolute paths, `..`, symlinks, hardlinks or device files; size cap 1 MiB).
- The sealed-config checks, as one function both `seal` and the helper call: insecure flags off, signer configured and trusted, resource policy present at its exact key, non-empty and not upstream's default.

## Spec

`IMPLEMENTATION_SPEC.md` §3 item 4 (sealed-config checks), §5 UNSEALING, §6 `seal`; ADR 0002, 0004, 0008.

## Done when

- [ ] The ticket 05 template passes the checks; each single violation fails them (AT-27, `seal` side).
- [ ] Extraction rejects every unsafe entry type and oversize input (AT-14).
- [ ] Sealing with the stock `age` CLI produces a bundle this package unseals.
- [ ] the Go gate exits 0.
