# 14: Claim profiles for every TEE type

**What to build:** `policy build` produces a correct resource policy for every supported TEE type, not just tpm. For tdx, snp, az-snp-vtpm, az-tdx-vtpm and tpm, document at the pinned Trustee version the claim paths and types for the Init-Data digest, the digest transformation, the debug check and the required reference values. The generated policy denies when a required claim is missing.

**Blocked by:** 05

**Status:** done

**Spec:** §6 claim profiles, §9 Phase 3.

- [x] A profile table cites the pinned verifier source for each TEE type.
- [x] Each profile has fixtures for matching evidence, a wrong Init-Data digest, debug on and a missing claim; only the matching fixture gets a release (AT-28).
- [x] Profiles without fixtures are marked untested; production Operator Policies may not accept them.
- [x] the Go gate exits 0.

## Comments

### What landed

- **Profile table:** `docs/claim-profiles.md`. It covers tpm, tdx, snp, az-snp-vtpm and az-tdx-vtpm at Trustee v0.22.0. For each type it gives the `init_data` claim, the digest transformation, the debug claim and its type, and the reference values the default AS policy needs to mark the evidence affirming. Every row cites a file and line at the tag. The code is the `profiles` table in `pkg/policy/policy.go`.
- **Resource policy:** one `allow` rule per accepted TEE type. Each rule needs `ear.status == "affirming"`, the transformed Init-Data digest, debug off (tpm has no debug claim), and each claim that a required reference value covers. The values sit in one `reference_values` object, one value per line. `policy build` refuses a missing required reference value for any accepted type.
- **Reference values are JSON values now** (`map[string][]any`). The SNP verifier reports TCB versions as numbers, and the default AS policy compares them with `in`. With string-only values, SNP evidence could never be affirming.
- **Untested profiles:** all five profiles are `untested`, tpm included. tpm has run only on swtpm, whose keys live on the host, and spec §11 says TPM-only evidence never counts. `policy build` refuses an untested profile unless the operator passes `--allow-untested-profiles`, which marks the policy non-production. This is the smallest mechanism: one flag, no new field in the Operator Policy. `share-release.sh`, `trustee-cvm.sh` and the in-process tracer pass the flag. Ticket 17 sets `untested` to false for the TEE type its real-TEE run passes on.
- **Fixtures (AT-28):** `test/e2e/profiles/testdata/<tee>.json`. Each file holds the matching EAR claims, the changes that must be denied (wrong Init-Data, debug on, not affirming; for tpm an untrusted AK in place of debug on) and the required claims, which the test deletes one at a time. `testdata/gen.py` derives the values from the source formulas, independently of `pkg/policy`; rerunning it leaves the files unchanged. No hardware produced them. tpm has no debug-on case because TPM evidence has no debug state.
- **Engine:** the pinned KBS image itself. The test builds one Operator Policy that accepts all five types, starts the Operator Verifier with `verifier.Runtime`, signs each fixture with that run's AS signer key (`x5c` holding the trusted cert, as the AS does), and requests the Share. Only the matching claims may get HTTP 200; every other case must get `PolicyDeny`. This runs regorus 0.11.0 exactly as KBS v0.22.0 does, with the real token path, so no second Rego engine has to be pinned and kept in step. `ci.sh e2e` runs it first (`go test ./test/e2e/profiles -args -engine podman`). Plain `go test` runs only the engine-free check.

### Found on the way

- **regorus refuses lines wider than 1024 columns** (regorus 0.11.0 `src/lexer.rs` `advance_col`; a tab counts as 4). The first fixture run failed for every case: the one-line `reference_values` object was 1197 columns, KBS could not load the policy, and it denied everything. The old tpm `expected := [...]` line had the same limit, so a few real AKs would have broken it. `policy build` now writes one value per line and refuses any line wider than 1023 columns. A probe on the pinned KBS confirmed the boundary: a 1023-column line loads, a 1024-column line does not.
- **TDX binds Init-Data only through MRCONFIGID** at v0.22.0. A TD that puts it only in RTMR3 reports a zero `init_data` and is denied. The tdx wrong-Init-Data fixture is that case.
- **az-snp-vtpm:** the default AS policy has no debug check; the resource policy adds one. The debug claim is the string `"false"`.

### Run on the scratch VM

```sh
vmsync <worktree> t14/src
vmssh 'cd ~/t14/src && PATH=$HOME/sdk/go/bin:$PATH go test -count=1 ./test/e2e/profiles -v -args -engine podman'
```

60 cases passed: 5 matching, 15 denied changes, 40 missing claims.

Full `ci.sh e2e` on the VM (`E2E_CACHE=~/t07/cache/e2e ./repo/test/e2e/ci.sh e2e` in `~/t14`): run 3 exited 0. After tpm became untested and the scripts gained `--allow-untested-profiles`, run 4 exited 0 too (log `~/t14/e2e.log`). The profiles test passed first. share-release.sh and trustee-cvm.sh passed with the new tpm rule: AT-03 and AT-13 released over swtpm, and AT-04 and AT-24 denied. Run 1 released AT-03, then failed AT-18 on a KBS container that my own earlier probe had leaked (a `| head` killed that `go test` before its stop ran). Run 2 failed before any policy ran: the Kata pod sandbox timed out on the 6 GB VM.

### Gate

the Go gate against `trustee-bootstrap`: PASS (golangci-lint 0 issues, gremlins 6 killed / 0 lived / 0 not covered, jscpd no new clones).
