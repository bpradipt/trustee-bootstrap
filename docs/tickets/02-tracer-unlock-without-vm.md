# 02: Tracer: unlock from Share payloads, no VM

**What to build:** the thinnest working Unlock Ceremony, run in one Go test. The Ceremony Authority runs `ceremony split` for 2-of-3. The Infrastructure Operator runs `seal` on a small config tree. A Bootstrap Helper, fed Share payloads by a fake CDH, combines two Shares, unseals the bundle and publishes the tree with its completion marker. This ticket also creates the Go module, the standalone binary and the exported command tree that `cococtl` will mount.

Keep the checks minimal: commitment, index and `key_id` validation lands in ticket 08; bundle and manifest integrity in 09; sealed-config checks in 10; crash handling in 11.

**Blocked by:** None (can start immediately)

**Status:** done

**Spec:** §3 items 1-5, §5, §6 (`ceremony split`, `seal`), §8; ADR 0001, 0002, 0003, 0006.

- [x] `ceremony split` writes the Share files and the Ceremony Manifest and never writes the age identity to disk.
- [x] `seal` produces a bundle that the stock `age` CLI can also produce, and prints its SHA-256.
- [x] With two valid Share payloads, the helper publishes the unsealed tree and exits 0 (AT-13, in-process).
- [x] With one, it stays locked (AT-12, in-process).
- [x] the Go gate exits 0.

## Comments

- **the Go gate against `trustee-bootstrap` exits 0:** golangci-lint 0 issues, gremlins 60 killed and 0 lived, jscpd no new clones. It ran with the pinned tools installed under a scratch `HOME`, because the agent sandbox can't read `its tools directory`.
- **Stock `age`.** The `age` CLI is not installed. `seal` writes a tar of the tree encrypted with `age.Encrypt` in age's binary format, which is what `tar -C dir -cf - . | age -r <recipient>` writes. `TestSealOutputIsStandardAge` decrypts the `seal` output with `age.Decrypt` and the identity rebuilt from two Shares. `TestUnsealAcceptsStockAgeBundle` builds a bundle the way the stock tools do (GNU tar's `./` names, then `age.Encrypt`), and `Unseal` accepts it. No test runs the `age` binary itself.
- **"Exits 0".** The helper binary needs the relay that ticket 03 adds, so this ticket ships no `cmd/bootstrap-helper`. In process, `Helper.CollectShare` returns `true, nil` once it has published the tree. `cmd/trustee-bootstrap` is the standalone CLI.
- **Fake CDH.** The sandbox denies TCP `bind`, so `httptest.NewServer` fails. The fake CDH is an `http.Handler` served through an in-process `http.RoundTripper`. The helper reaches the CDH through `helper.CDH{URL, Client}`; ticket 03 passes `http://127.0.0.1:8006` and a real client.
- Left for later tickets, as planned: Share validation, duplicate indices and the manifest validator (08); the `--manifest-sha256` pin, `bundle_sha256` and the size caps (09); sealed-config checks and the full safe-extraction rules (10); fsync, staging cleanup and the restart path (11). `Unseal` already extracts only directories and regular files, and it extracts through `os.Root`, which keeps every path inside the staging directory.
- Review fixes: the package names (`helper`, `cli`, `seal` and the rest) stay. The review suggested
  renames; they would churn every import and the cococtl patch for no behaviour change.
