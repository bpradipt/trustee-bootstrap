# 10: Sealed-config checks and safe extraction

**What to build:** nobody can unlock a Trustee that runs an unsafe config or a booby-trapped tree. One check function, called by both `seal` and the helper before publishing, refuses:
- insecure KBS token, HTTP or admin settings;
- a missing AS signer, or one whose certificate KBS doesn't trust;
- a resource policy that is missing, misplaced, empty or equal to upstream's default.

Unsealing refuses absolute paths, `..`, symlinks, hardlinks, device files and anything over the size cap. The check reads its key names from the default secure configs delivered by tickets 05 and 06.

**Blocked by:** 02, 05

**Status:** done

**Spec:** §3 item 4 (sealed-config checks), §5 UNSEALING, §6 `seal`; ADR 0008.

- [x] AT-14 and AT-27 pass, including a bundle sealed with stock `age` that the helper refuses.
- [x] Each sealed-config check fails on its own violation and passes on the default secure Trustee config.
- [x] the Go gate exits 0.

## Comments

- `verifier.CheckSealedConfig(dir, root)` is the one check function. It decodes `kbs.toml` from the tree into
  `verifier.Config` and runs `CheckSecure` (`insecure_header_jwk`, admin mode) plus `insecure_http`. It then
  checks that the AS signer key and certificate are in the tree and that `trusted_certs_paths` lists the
  certificate. Last, it checks the resource policy: `storage_type = "LocalFs"`, the file
  `<dir_path>/kbs/resource-policy.rego` is in the tree, it is non-empty, and it isn't KBS's default.
- `root` is where Trustee will see the tree. Config paths are absolute, so the check maps each one into `dir`
  and refuses a path outside `root`. The helper passes its `--out`, because in the example pod the helper and
  Trustee mount the state volume at the same path. `seal` takes `--root`, which defaults to
  `verifier.TrusteeRoot` (`/trustee/config`, the example pod's `--out`).
- "Upstream's default" is `kbs/sample_policies/default.rego` at Trustee v0.22.0
  (commit `512fed65642015b849f38fb13bfdec7806639987`). KBS embeds it with `include_str!` in
  `kbs/src/api_server.rs`. It is embedded byte for byte as `pkg/verifier/kbs-default-resource-policy.rego`
  (sha256 `499ca028…6c60`, checked by a test). The comparison ignores comment lines and whitespace, so a copy
  with the header removed or re-indented is still refused. A rewritten but equivalent policy would pass.
- `seal.Unseal` refuses names that aren't local or that hold a `..` element, and every entry type except
  directories and regular files (symlink, hardlink, char, block, fifo). It also refuses file contents over
  `seal.MaxSize` (1 MiB) in total. age doesn't compress, but a PAX sparse entry can unpack larger than its
  bytes, so the cap counts each header's size. `cmd/bootstrap-helper` caps the files with the same constant.
- On any failure after `Combine`, the helper removes the staging directory (spec §5 "wipe staging"). The
  check runs on the staged tree before the completion marker and the rename.
- Tests: `internal/trusteetest` has `Tree(t, root)`, a tree that passes, and `Violations`, one per check.
  `pkg/verifier` runs each violation (it must fail only its own check) and the example `kbs.toml` (it must
  pass). `pkg/cli` checks that `seal` refuses each violation and writes no bundle. `pkg/helper` seals each
  violation with `seal.Seal`, which is tar plus `age.Encrypt` with no checks, the same as stock `age`. The
  helper ends FAILED with neither `out` nor staging on disk (AT-27). AT-14: `pkg/seal` has one test per hostile
  entry, a corrupt bundle, and the size cap (exact cap passes, over it fails). `pkg/helper` has a sealed
  symlink that fails the unlock and leaves nothing behind.
- Not checked: unknown keys in `kbs.toml`. The check reads only the keys `verifier.Config` models. Spec §3
  lists only those, and we rely on shipping default secure configs instead of tracking every KBS option.
- `share-release.sh` sealed a one-file tree, so `seal` now refuses it. It now seals a minimal valid tree for
  the helper's `--out /tmp/trustee`. `trustee-cvm.sh` already sealed a passing tree.
- the Go gate against `trustee-bootstrap`: PASS, exit 0 (gremlins 26 killed, 0 lived, 0 not covered).
- `ci.sh e2e` passed on the scratch VM: share-release PASS and trustee-cvm PASS. Both helpers ran the checks
  before publishing. To repeat: `vmsync <worktree> t10/src`, then on the VM
  `cd ~/t10/src && PATH=$HOME/sdk/go/bin:$PATH E2E_CACHE=$HOME/t07/cache/e2e test/e2e/ci.sh e2e`.
