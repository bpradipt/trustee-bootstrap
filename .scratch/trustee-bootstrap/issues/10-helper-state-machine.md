# 10 Bootstrap Helper state machine

Status: open
Type: task
Blocked by: 07, 08, 09

## What

`pkg/helper/` and `cmd/bootstrap-helper/`, tested against a fake CDH.

- On start: exit 0 if the marked published tree exists; otherwise wipe staging.
- LOCKED: fail closed if `--manifest-sha256` is missing or empty. Read manifest and bundle into memory once, with a cap; verify the manifest digest; hash the bundle. Draw `boot_id`.
- COLLECTING: on relay open, call the CDH resource endpoint for `trustee-bootstrap/share/current`. Accept a payload only if `key_id` matches, the index is in the manifest and new, the Share matches its commitment, and `bundle_sha256` matches the in-memory bundle. Optional `--deadline`. Released Shares are irrevocable for the boot.
- UNSEALING: `shamir.Combine`, unseal the in-memory bytes, run the sealed-config checks.
- PUBLISHED: modes and ownership, marker into staging, fsync, atomic rename, exit 0.
- `GET /bootstrap/v1/status` with no secrets.

## Spec

`IMPLEMENTATION_SPEC.md` §4, §5; ADR 0003, 0004, 0007.

## Done when

- [ ] Unit tests pass for AT-07, AT-08, AT-09, AT-10, AT-11, AT-12, AT-13, AT-14, AT-15, AT-23, AT-26 and the helper side of AT-27.
- [ ] the Go gate exits 0.
