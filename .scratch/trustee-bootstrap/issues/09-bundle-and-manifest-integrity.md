# 09: Bundle and manifest integrity

**What to build:** the host can't make the Trustee CVM unseal anything but the Approved Bundle. The helper refuses to start when `--manifest-sha256` is missing, empty or doesn't match. It reads the manifest and the bundle into memory once, with a size cap, and hashes and decrypts only those bytes. It accepts a Share only if its `bundle_sha256` matches the in-memory bundle. A released Share stays valid for the rest of the boot; `--deadline` is optional cleanup.

**Blocked by:** 02

**Status:** done

**Spec:** §5 LOCKED and COLLECTING; ADR 0004, 0007.

- [x] AT-09, AT-10, AT-11 and AT-23 pass.
- [x] Swapping either file on disk after LOCKED changes nothing the helper does.
- [x] the Go gate exits 0.

## Comments

- `helper.New(manifest, manifestSHA256, bundle, out, cdh)` is LOCKED. It checks hex `sha256(manifest)` against
  `--manifest-sha256` first. A missing or empty flag fails the same check. Then it validates the manifest and
  computes the bundle digest. `Helper.check` rejects a payload whose `bundle_sha256` is not that digest. The
  check runs last, after the Share Commitment.
- `cmd/bootstrap-helper` reads each file once through `readCapped`, with a 1 MiB cap (spec §3 item 4). The helper
  keeps only those bytes. `run` now also takes the CDH's `*http.Client`, so a test can drive the whole binary.
- `--deadline` (a Go duration, default 0 = none) is passed to `Serve`. When it expires, the helper clears the
  accepted Shares, enters FAILED and exits 1. It is cleanup, not a security control (spec §5).
- Tests: `TestBadShareRejectedAndReported` gains `bundle_sha256` cases (AT-09, AT-10 on a fresh boot).
  `TestNewRejectsManifestDigestMismatch` and the `run` cases cover AT-11 (swapped manifest, flag dropped).
  `TestServeWithoutDeadlineKeepsAcceptedShares` covers AT-10 within one boot. `TestRunUnsealsTheBundleReadInLocked`
  covers AT-23: after LOCKED it overwrites the bundle with a host bundle sealed to the same recipient and
  the manifest with `{}`, then two relays publish the approved tree. `TestServeFailsWhenUnsealFails` now gives
  the payloads the other bundle's digest, so only unseal fails. `TestServeDeadlineDiscardsShares` and
  `TestRunFailsAtDeadline` cover `--deadline`.
- Pod level: `deploy/examples/trustee-cvm.yaml` pins `--manifest-sha256=@MANIFEST_SHA256@`. `trustee-cvm.sh`
  fills it in from `sha256sum ceremony.json` before genpolicy runs, and `share-release.sh` passes the flag.
  The new `check_swapped_manifest` step (AT-11) puts another Key Ceremony's `ceremony.json` in the ConfigMap,
  under the same pod and policy, and checks that the helper init container exits 1 and never serves status.
- The helper compares `bundle_sha256` exactly. So `policy build` now refuses a `--bundle-sha256` that is not 64
  lowercase hex characters. An operator who types an uppercase digest finds out at build time, not at unlock.
- the Go gate against `trustee-bootstrap`: PASS, exit 0 (gremlins 14 killed, 0 lived, 0 not covered).
- `ci.sh e2e` passed on the scratch VM: share-release PASS, and trustee-cvm PASS with the new AT-11 step. The
  agent policy pins the new arg, since the pod with it unlocked. To repeat: `vmsync <worktree> t09/src`, then
  on the VM `cd ~/t09/src && PATH=$HOME/sdk/go/bin:$PATH E2E_CACHE=$HOME/t07/cache/e2e test/e2e/ci.sh e2e`.
