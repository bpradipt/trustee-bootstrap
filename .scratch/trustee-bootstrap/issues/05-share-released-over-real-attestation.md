# 05: Share released over real attestation

**What to build:** a Security Operator's Share leaves their machine only after real Bootstrap Attestation. In the swtpm environment, a test pod's stock CDH asks for the Share through the guest proxy and relay from ticket 03. On the operator side the stub server is replaced by the real Operator Verifier: the pinned Trustee KBS image on `127.0.0.1`, run with the default secure Operator Verifier config. `policy build` generates that verifier's resource policy for the tpm claim profile, computing the Init-Data digest from the reviewed Init-Data TOML.

The default secure config sets `insecure_header_jwk = false`, requires the ephemeral admin key, and wires a per-run AS signer whose certificate KBS trusts. This ticket delivers it; ticket 06 derives the Trustee config from it, and ticket 10's checks read their keys from it.

**Blocked by:** 03, 04

**Status:** done

**Spec:** §3 item 6, §4 step 2, §6 (`policy build`, claim profiles, Operator Verifier runtime); ADR 0005.

- [x] With matching Init-Data, the pod's CDH receives the Share payload through the relay (AT-03).
- [x] With changed Init-Data, the Operator Verifier denies it (AT-04).
- [x] A capture of all relay traffic contains no Share bytes (AT-06).
- [x] The Operator Verifier runs as a digest-pinned container by default, or from `--kbs-binary`.
- [x] Notes on RCAR connection behaviour (connections per exchange, reconnects, timing) go into ticket 12's Comments.
- [x] the Go gate exits 0.

## Comments

### What landed

- `pkg/policy`: `Build` turns the reviewed Init-Data TOML, reference values, accepted TEE types, bundle digest, Ceremony Manifest and Share file into an `OperatorPolicy`. It refuses an Init-Data `algorithm` other than `sha256`, any TEE type but `tpm`, a missing `trusted_aks` or `tpm_pcr11`, a reference value name outside `[A-Za-z0-9_.-]`, a bad bundle digest, and a Share that doesn't match its Share Commitment. `Write` and `Load` keep the policy in a `0700` directory as `operator-policy.json` plus `resource-policy.rego`.
- The tpm claim profile's resource policy requires `submods.cpu0["ear.status"] == "affirming"`, `init_data == sha256(0³² ‖ sha256(Init-Data))` (PCR8), and the AK and PCR11 among the operator's reference values. TPM evidence reports no debug state, so the profile has no debug check. Ticket 14 adds the other profiles.
- `pkg/verifier`: `Config`, `DefaultConfig` and `CheckSecure` hold the default secure Operator Verifier config. Tickets 06 and 10 read the key names from these Go types. The config sets `insecure_header_jwk = false`, `trusted_certs_paths` to a per-run self-signed P-256 AS signer certificate, the AS `attestation_token_broker.signer` to that key and certificate, admin `AuthenticatedAuthorization` with an Ed25519 key whose private half is never kept, `LocalFs` storage in the run directory and `session_storage_type = "Memory"`. `Runtime.Start` writes the run directory under `$XDG_RUNTIME_DIR` (else `/dev/shm`), refuses a config that fails `CheckSecure`, and runs KBS. Without `--kbs-binary` it runs `podman` (else `docker`) `run --rm -p 127.0.0.1:<port>:8080` on the pinned image. It returns once KBS answers HTTP, and its stop function sends SIGTERM and deletes the run directory.
- KBS gets its state from files, not the admin API: `storage/kbs/resource-policy.rego`, `storage/repository/trustee-bootstrap\x2Fshare\x2Fcurrent` (the Share payload) and `storage/reference_value/<name>` (RVPS's stored JSON form). Trustee v0.22.0 sources: `kbs/src/api_server.rs` (`KBS_POLICY_ID`, installs its default only when the key is absent), `deps/key-value-storage/src/local_fs`, `rvps/src/reference_value.rs`.
- CLI: `policy build ... --out-dir DIR` and `approve --endpoint URL --policy DIR --share-file FILE [--kbs-binary PATH]`. `approve` checks the Share against the Operator Policy before it calls the helper or starts anything.

### Deviations from the spec

- `policy build` needs `--out-dir`, which spec §6 doesn't list.
- `policy build` doesn't write a KBS config. The config holds per-run paths, the port and fresh keys, so `approve` generates it each run from `DefaultConfig`. The RVPS values live in `operator-policy.json`.

### Run on the scratch VM

`test/e2e/share-release.sh` runs against the ticket 04 cluster. The Bootstrap Helper runs as a plain process in a busybox Kata pod with the TPM runtime class and the test's Init-Data. The pod fetches the helper binary, `ceremony.json` and the Sealed Bundle from a file server on the kind gateway. Operators reach it through a NodePort with `publishNotReadyAddresses`. Ticket 06 replaces all of this with the real Trustee CVM pod.

```sh
vmsync <worktree> t05/repo
vmssh 'cd ~/t05 && E2E_CACHE=~/t04/cache/e2e ./repo/test/e2e/kind-kata-swtpm.sh up && PATH=$HOME/sdk/go/bin:$PATH ./repo/test/e2e/share-release.sh'
```

It printed `PASS`:

- **AT-03:** alice (pinned image through rootless podman) and carol (`--kbs-binary`) each got `accepted`. The helper went `COLLECTING []` → `[1]`, then published and exited 0.
- **AT-04:** with a comment line added to the Init-Data, `approve` failed with "Share not accepted" and the status stayed `COLLECTING []`. A debug run of the same KBS showed why: the EAR status was `Affirming`, the claim `init_data` was `2158a57b…`, the policy expected `bcdc2082…`, and KBS answered `PolicyDeny`. Attestation passed and the resource policy denied, which is the case AT-04 asks for.
- **AT-06:** `tcpdump -i any` (all TCP except ssh) ran across both approvals. It caught the relay WebSocket on the podman bridge and, on `lo`, the plaintext HTTP between the CLI and KBS that the relay carries. The capture holds `/bootstrap/v1/relay`, `/kbs/v0/attest` and the JWE `"ciphertext"`. It holds no Share in raw, base64 or base64url form.
- After the run, no verifier container and no run directory under `/run/user/1000` remained.

### Not done or not proven

- **`--kbs-binary` ran through a wrapper.** The image's `kbs` links `libsgx_dcap_quoteverify.so.1`, which the VM lacks. The test's `--kbs-binary` is a script that runs the image's `kbs` with `--network host`. That exercises the native path: host paths in the config, the socket on `127.0.0.1:<port>`, and the process lifecycle. A truly native `kbs` is untested.
- **swtpm is not a TEE.** These results prove the plumbing and the policy logic. They don't count as a real-TEE result (ticket 17).
- **Unit tests can't listen on TCP in the sandbox.** `Runtime.Start` tests run fake `kbs` and engine scripts with an in-memory listener and probe. The real listener, podman and KBS ran only on the VM. Ticket 07 must run `share-release.sh` in CI.
- **Hardening is ticket 13.** The CLI doesn't check that the run directory is on tmpfs. A rootful docker would leave root-owned files in it that the CLI can't delete. KBS output stays in an unbounded in-memory buffer, shown only if KBS exits before it answers. Nothing tests SIGINT cleanup, forged tokens or admin calls yet.
- **Gate:** the Go gate against `trustee-bootstrap` exited 0 (74 mutants killed, 0 lived, 0 not covered, 1 timed out). `go vet ./...` and `go test ./...` pass.
