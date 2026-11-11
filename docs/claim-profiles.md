# Claim profiles

`policy build` writes one `allow` rule per accepted TEE type into the Operator Verifier's resource policy. Each rule follows that TEE type's claim profile (spec §6). This page records each profile at the pinned Trustee version, **v0.22.0** (`512fed65`, see `docs/upstream-pins.md`), and cites the source it comes from. The code is the `profiles` table in `pkg/policy/policy.go`.

Every path below is relative to the Trustee repository at that tag.

## What every rule checks

KBS evaluates `data.policy.allow` with the verified token's claims as `input` (`kbs/src/api_server.rs:39`, `:411`, `:419`). The claims are an EAR token: the built-in AS puts each TEE's claims under `submods.cpu0["ear.veraison.annotated-evidence"]`, keyed by the TEE type (`attestation-service/src/ear_token/broker.rs:445` `transform_claims`, `:497`). The same function moves the verifier's `init_data` claim up to the annotated evidence's top level (`:461`). So every rule reads:

- `cpu0["ear.status"] == "affirming"`. The default AS policy (`attestation-service/src/ear_token/ear_default_policy_cpu.rego`) sets this only when its trust claims for the TEE type hold. It needs the reference values in the table below.
- `evidence.init_data`, equal to the Init-Data digest after that TEE's transformation.
- The debug claim, where the TEE has one.
- Each claim the default AS policy checks against a required reference value, checked again against the same values.

A rule fails when any claim it reads is missing, because the condition is undefined. `default allow := false` covers the rest.

The Init-Data digest is `sha256` of the Init-Data TOML bytes (`attestation-service/src/lib.rs:362` `parse_init_data`, `:369`). `policy build` accepts only `algorithm = "sha256"`. The TPM-based verifiers compute `sha256(0^32 || digest)` over a 32-byte digest, so sha384 and sha512 do not work for them.

## Profiles

| TEE type | `init_data` claim | Digest transformation | Debug check | Required reference values (claim checked) | Tested |
|---|---|---|---|---|---|
| `tpm` | PCR8, hex (`deps/verifier/src/tpm/mod.rs:21`, `:242`) | `sha256(0^32 ‖ digest)` (`tpm/mod.rs:157` `verify_init_data`) | none: TPM evidence has no debug state (`tpm/mod.rs:239` `parse_tee_evidence`) | `trusted_aks` (`tpm.ak_public`), `tpm_pcr11` (`tpm.pcr11`) (default policy `:306`) | untested: swtpm runs only (tickets 05, 06) |
| `tdx` | MRCONFIGID, hex (`deps/verifier/src/tdx/claims.rs:182`) | `digest ‖ 0^16`: the verifier pads the digest to MRCONFIGID's 48 bytes (`tdx/mod.rs:115`; `deps/verifier/src/lib.rs:317` `regularize_data`) | `tdx.td_attributes.debug == false` (bool; `tdx/claims.rs:179`, `:194`, `:202`) | `rtmr_1`, `rtmr_2` (`tdx.quote.body.rtmr_1`, `rtmr_2`), `mr_td` (`tdx.quote.body.mr_td`), `xfam` (`tdx.quote.body.xfam`) (default policy `:150`) | untested |
| `snp` | HOST_DATA, hex (`deps/verifier/src/snp/mod.rs:657`) | none: HOST_DATA is the 32-byte digest (`snp/mod.rs:528`) | `snp.policy_debug_allowed == false` (bool; `snp/mod.rs:641`) | `snp_launch_measurement` (`snp.measurement`), `snp_bootloader`, `snp_microcode`, `snp_snp_svn`, `snp_tee_svn` (`snp.reported_tcb_*`, numbers) (default policy `:101`) | untested |
| `az-snp-vtpm` | vTPM PCR8, hex (`deps/verifier/src/az_snp_vtpm/mod.rs:40`, `:90` `extend_claim`) | `sha256(0^32 ‖ digest)` (`az_snp_vtpm/mod.rs:391` `verify_init_data`) | `["az-snp-vtpm"].policy_debug_allowed == "false"` (a **string**; `az_snp_vtpm/mod.rs:420`) | `measurement`, `snp_pcr11` (`tpm.pcr11`), `tcb_bootloader`, `tcb_microcode`, `tcb_snp`, `tcb_tee`, `smt_enabled`, `tsme_enabled`, `abi_major`, `abi_minor`, `single_socket`, `smt_allowed` (all strings) (default policy `:241`) | untested |
| `az-tdx-vtpm` | vTPM PCR8, hex (`deps/verifier/src/az_tdx_vtpm/mod.rs:100`, `:101`) | `sha256(0^32 ‖ digest)` (`az_tdx_vtpm/mod.rs:98`, the az-snp-vtpm `verify_init_data`) | `["az-tdx-vtpm"].td_attributes.debug == false` (bool; `tdx/claims.rs:179`) | `tdx_pcr11` (`tpm.pcr11`), `mr_td`, `xfam` (`quote.body.*`) (default policy `:274`) | untested |

Notes:

- **tdx.** At v0.22.0 the TDX verifier binds Init-Data only through MRCONFIGID. A TD that measures Init-Data into RTMR3 and leaves MRCONFIGID zero reports `init_data` as 48 zero bytes, and the rule denies it. The fixtures test exactly that case.
- **tdx.** The default AS policy also needs `tcb_status == "UpToDate"` and `collateral_expiration_status == "0"` for affirming. These come from Intel collateral, not from reference values. `tdvfkernel` and `tdvfkernelparams` are optional: without them, `executables` is 4, which is still affirming. The EAR crate (ear 0.5.0, `src/trust/claim.rs:447`) counts 2 to 31 as affirming, and the status is the worst tier of the trust vector.
- **snp.** The default AS policy compares the reported TCB claims, which are numbers, with the reference values. Give `snp_bootloader`, `snp_microcode`, `snp_snp_svn` and `snp_tee_svn` as JSON numbers, not strings, or the evidence is never affirming. Reference values are JSON values for this reason. Without the optional `snp_smt_enabled` and related values, `configuration` falls to 3, which is still affirming.
- **az-snp-vtpm.** The default AS policy does not check debug for this type. The resource policy does. If the vTPM quote has 8 PCRs or fewer, the verifier leaves `init_data` as base64 HOST_DATA, and the rule denies it.
- **az-snp-vtpm, az-tdx-vtpm.** These types report every SNP policy bit and TCB version as a string, so their reference values are strings.

## Untested profiles

No profile has passed a real-TEE run, so all five are untested. The four hardware profiles come from reading the verifier source. The tpm profile has passed swtpm runs, but swtpm keys live on the host, and spec §11 says synthetic or TPM-only evidence never counts as security completion. A production Operator Policy may accept only a TEE type whose profile has passed a real-TEE run (spec §9 Phase 3).

So `policy build` refuses every profile unless the Security Operator passes `--allow-untested-profiles`. That flag says the policy is not a production Operator Policy. The policy records it as `"untested_profiles": true` in `operator-policy.json`, and `approve` prints a warning when it loads such a policy. The e2e scripts pass it, because they run on swtpm. A profile becomes tested only when ticket 17's real-TEE run passes on that TEE type: set `untested: false` in `pkg/policy/policy.go` and record the run in the table above.

## Attestation collateral (gap)

TDX and SNP evidence verifies only against the vendor's collateral: Intel PCS or a PCCS for TDX, AMD KDS or offline VCEK/VLEK files for SNP (spec §6). The Operator Verifier config that `approve` generates sets none of Trustee's collateral settings, so it uses Trustee's built-in defaults. Nothing here has run against real collateral. Ticket 17's real-TEE run must set the collateral source through Trustee's own settings in the generated Operator Verifier config before a TDX or SNP profile can pass.

## Fixtures (AT-28)

`test/e2e/profiles/testdata/` holds one file per TEE type. Each file holds:

- the matching EAR claims for `testdata/init-data.toml` and `testdata/reference-values.json`;
- changes that must be denied: a wrong Init-Data digest, debug on (not for tpm), status not affirming, and for tpm an untrusted AK;
- the required claims, which the test deletes one at a time.

`testdata/gen.py` derives the values from the formulas above, independently of `pkg/policy`. Its header says how to run it; rerun it and check that `git diff` is empty. No hardware produced the values.

`go test ./test/e2e/profiles -args -engine podman` builds one Operator Policy that accepts all five types and starts the Operator Verifier with it, which runs the pinned KBS image. It then signs each fixture's claims with that run's AS signer key and asks for the Share. Only the matching fixtures may get it; every other request must get `PolicyDeny`. Running the real KBS means the policy goes through the same Rego engine KBS uses (regorus 0.11.0, per Trustee's `Cargo.lock`) and the same token path, with no second Rego implementation to keep in step. `ci.sh e2e` runs it. Without `-engine`, only an engine-free check runs, which tests that each fixture's `init_data` appears in the generated policy.

## KBS Rego engine limit

regorus 0.11.0 refuses a policy line wider than 1024 columns, counting from 1, and it counts a tab as 4 columns (`src/lexer.rs` `advance_col`). A policy that fails to load denies every request. `policy build` writes one reference value per line and refuses a policy with a line wider than 1023 columns. A run on the pinned KBS confirmed the boundary: a 1023-column line loads, a 1024-column line does not.
