# Trustee-in-CVM: Implementation Specification

**Status:** Design agreed; Phase 0 must confirm the upstream facts marked *(Phase 0)*  
**Version:** v1.0 (baseline) | **Date:** 2026-11-10  
**Companions:** `SECURITY_THREAT_MODEL.md`, `GLOSSARY.md`, `docs/adr/`

Terms in **bold** are defined in `GLOSSARY.md`. Design rationale lives in the ADRs and is not repeated here.

## 0. Mission and constraints

Unlock an unmodified, full CNCF Trustee running in a **Trustee CVM** only after K-of-N **Security Operators** have each independently appraised that CVM and released their **Share** to it. Each Security Operator runs an **Operator Verifier**: a stock Trustee KBS with its built-in AS, on their own workstation and bound to `127.0.0.1`. The Operator Verifier reaches the CVM through a tunnel that the operator's CLI opens outbound. Inside the CVM, a **Bootstrap Helper** init container collects the Shares, reconstructs the bootstrap private key, unseals the **Sealed Bundle** into guest memory, and exits so that Trustee can start.

### Non-negotiable requirements

1. Reuse Trustee's RCAR protocol, verifier, attestation token and JWE resource delivery unchanged. The Bootstrap Helper gets attestation only through the sandbox's CDH/AA. Do not write a parallel attestation protocol or custom crypto.
2. The Operator Verifier listens only on `127.0.0.1`. Every network connection across hosts is initiated by the CLI.
3. A Share leaves the operator's machine only as a JWE to the attested TEE key, and only after the appraisal succeeds.
4. The Bootstrap Helper accepts a Share only if `sha256(share)` matches its **Share Commitment** (ADR 0003). It unseals only the **Approved Bundle** that every accepted Share names (ADR 0004).
5. The **Ceremony Manifest** is trusted only if its digest equals the digest pinned in the Bootstrap Helper's container args, which Init-Data measures (ADR 0007).
6. Plaintext config, Shares and the reconstructed key never reach host-visible storage, logs, env, Kubernetes objects or API responses.
7. Pin every upstream version or digest. Fail closed whenever any check can't be performed.

## 1. Two uses of attestation

- **Bootstrap Attestation**: each Operator Verifier appraises the Trustee CVM: the TEE evidence, the Init-Data digest, and through Init-Data the Kata Agent policy, image digests and the Ceremony Manifest digest.
- **Workload Attestation**: the unlocked Trustee appraises other confidential workloads in normal service.

**How workloads trust Trustee:** Trustee's TLS private key exists only inside the Sealed Bundle. Workloads pin Trustee's certificate (`kbs_cert`) in their own Init-Data. So only a Trustee CVM that K Security Operators approved can ever present that identity. Rotating Trustee's certificate means sealing a new bundle and updating every workload's Init-Data.

## 2. Actors

| Actor | Where | Trusted for |
|---|---|---|
| **Ceremony Authority** | Air-gapped machine, once per Key Ceremony | Generating the key pair, splitting it into Shares, and retiring the private key |
| **Security Operator** | Own Linux/WSL workstation | Their own Share, and their own Operator Policy |
| **Infrastructure Operator** | Anywhere | Nothing with respect to Shares. Authors the plaintext config and seals it |
| Kubernetes, host and network | — | Nothing. May drop, replay, reorder or substitute anything |
| **Bootstrap Helper** | Init container in the Trustee CVM | Only once Bootstrap Attestation has verified it |
| CDH/AA | Trustee CVM sandbox (stock CoCo) | RCAR client; holds the TEE key |
| Trustee | Main container in the Trustee CVM | Normal service after unlock (unmodified) |

## 3. Artifacts

All formats are owned by one Go module in this repo (ADR 0001, ADR 0006).

1. **Bootstrap key pair**: an age X25519 identity and its recipient. The identity's bytes are split with `github.com/hashicorp/vault/shamir`.
2. **Ceremony Manifest** (`ceremony.json`, public and unsigned):
   ```json
   {"version":1,"key_id":"…","threshold":2,"recipient":"age1…",
    "shares":[{"index":1,"holder":"alice","commitment":"sha256:…"}, …]}
   ```
   - `index` is the position in this list, and `holder` is a label for audit only.
   - The Bootstrap Helper rejects the manifest if indices or commitments repeat, if `threshold < 2`, or if `threshold > len(shares)`.
3. **Share file** (one per Security Operator, `0600`): `{"version":1,"key_id":"…","index":1,"share":"<base64 Vault part>"}`.
4. **Sealed Bundle**: `age -r <recipient>` over a tar of Trustee's config tree. Paths are relative to Trustee's config root.
   - It contains the KBS config, resource policy, RVPS reference values, resources, admin public key, and Trustee's TLS key and certificate.
   - Its digest is `sha256` of the sealed file's bytes.
   - It is Trustee's **entire** state (ADR 0002).
   - Size cap: 1 MiB, because it travels in a ConfigMap or Secret.
5. **Share payload**: the plaintext of the KBS resource that the Operator Verifier serves:
   `{"version":1,"key_id":"…","index":1,"share":"…","bundle_sha256":"…"}`.
   It travels only as Trustee's standard JWE to the attested `tee-pubkey`.
6. **Operator Policy**: produced locally by `policy build` (§6). It holds:
   - the accepted TEE types;
   - the reference values;
   - the Init-Data digest, which the CLI computes from a reviewed Init-Data TOML, never from a pasted hash;
   - the Approved Bundle digest;
   - the `key_id` and the operator's own index.

## 4. Transport

### Helper API (plain HTTP; ADR 0005)

| Endpoint | Purpose |
|---|---|
| `GET /bootstrap/v1/status` | Returns `{boot_id, key_id, state, threshold, accepted:[index…]}`. Contains no secrets. Rate-limited. |
| `GET /bootstrap/v1/relay` | WebSocket upgrade. Only one relay may be open at a time; a second request gets `409`. Unauthenticated: squatting the relay is a DoS, which is out of scope (ADR 0003). |

`boot_id` is 128 random bits drawn when the Bootstrap Helper starts. It is used only to correlate status and audit records. TLS in front of the Bootstrap Helper (Ingress, LoadBalancer, port-forward) is allowed, but it is not a security boundary. The CLI accepts both `http://` and `https://`, and `--port-forward` as a convenience.

### One operator's flow

1. `approve` loads the Operator Policy and the operator's Share file. It checks that the Share's hash equals the manifest commitment for its index.
2. The CLI starts the Operator Verifier on `127.0.0.1:<random port>`, with:
   - `insecure_http = true`;
   - the operator's reference values and generated resource policy;
   - the Share payload as the only resource, at `trustee-bootstrap/share/current`, written to a `0700` tmpfs directory;
   - an ephemeral admin key that is thrown away.
3. The CLI calls `status`, checks `key_id` and that its own index has not been accepted yet, then opens the relay.
4. On relay open, the Bootstrap Helper starts its guest-loopback proxy (`127.0.0.1:<proxy port>`, the KBS URL in Init-Data's `aa.toml` and `cdh.toml`). It then calls `GET http://127.0.0.1:8006/cdh/resource/trustee-bootstrap/share/current`.
5. The CDH/AA run standard RCAR through the proxy, then the relay, then the Operator Verifier. The Operator Verifier's resource policy releases the payload only if the EAR claims show all of the following:
   - an accepted TEE type;
   - the expected Init-Data digest;
   - matching reference values;
   - debug disabled.
   The CDH decrypts the JWE and returns the payload to the Bootstrap Helper over loopback.
6. The Bootstrap Helper validates the payload (§5). It closes the proxy and the relay. The CLI tears down the Operator Verifier and wipes the tmpfs directory, then reports `accepted` or a sanitized error.

Operators run one after another. Each CDH call does a fresh RCAR with a fresh TEE key, because there is no caching. Nothing needs to be serialized beyond the single-relay rule.

### Relay framing

- Binary WebSocket messages with a 9-byte header: `type` (u8: `OPEN=1`, `DATA=2`, `CLOSE=3`), `conn_id` (u64 big-endian), then the payload.
- `DATA` frames carry at most 64 KiB.
- The guest side sends `OPEN` for each loopback connection that the CDH/AA make. `conn_id` must strictly increase. Only one inner connection is open at a time, and at most 8 per relay.
- The CLI connects only to its own Operator Verifier port. It never connects to an address taken from a frame.
- Limits: 30 s idle and 120 s total per relay. They can be configured lower but not disabled.
- Buffers are bounded with backpressure. A disconnect cleans everything up. Inner bytes are never parsed or logged.

## 5. Bootstrap Helper

Flags: `--manifest`, `--manifest-sha256`, `--bundle`, `--out`, `--listen`, `--proxy-port`, and an optional `--deadline`. All values are pinned by the Kata Agent policy. A missing or empty `--manifest-sha256` is fatal, because the policy lets the host drop args it can't change.

```text
LOCKED -> COLLECTING -> UNSEALING -> PUBLISHED -> exit 0
any failure -> FAILED -> wipe staging -> exit 1   (no partial config, ever)
```

- **LOCKED:** draw `boot_id`. Check that `sha256(manifest file) == --manifest-sha256`, and validate the manifest. Compute `sha256(bundle file)`.
- **COLLECTING:** accept a payload only if all of these hold:
  - `key_id` matches the manifest;
  - its `index` exists in the manifest and has not been accepted yet;
  - `sha256(share)` equals that index's commitment;
  - `bundle_sha256` equals the mounted bundle's digest.
  A payload that fails any check is rejected and **not** counted, and its index is reported in status and audit. Accepted Shares stay in memory only. There is no deadline unless `--deadline` is set.
- **UNSEALING:** at `threshold` Shares, run `shamir.Combine`, then age-decrypt the bundle and extract the tar into a staging directory on the output volume. Extraction rejects:
  - absolute paths and `..`;
  - symlinks, hardlinks and device files;
  - anything over the size cap.
  Wipe Shares and the key from memory on a best-effort basis.
- **PUBLISHED:** `0700` directory, files no wider than `0600`. Rename the staging directory into place atomically, stop the listeners, and exit 0.
- A restart of any kind gives a new `boot_id` and an empty Share set. Accepted Shares are never persisted.

## 6. CLI

This is one Cobra tree in `pkg/cli`, `NewTrusteeBootstrapCmd()`. `cococtl` mounts it as `cococtl trustee-bootstrap …` (and `kubectl coco trustee-bootstrap …`). This repo also builds a standalone `trustee-bootstrap` binary. Existing `cococtl` commands gain no new dependencies at startup.

| Command | Who | Does |
|---|---|---|
| `ceremony split --threshold K --holders a,b,c` | Ceremony Authority, air-gapped | Generates an age identity, splits it, writes the Share files and `ceremony.json`, and never writes the identity to disk |
| `seal --manifest ceremony.json <dir>` | Infrastructure Operator | Tars and age-encrypts the directory, and prints the bundle digest. The stock `age` CLI is an acceptable substitute |
| `policy build --init-data init.toml --reference-values rv.json --accept-tee tdx,snp --bundle-sha256 … --manifest ceremony.json --share-file my.share` | Security Operator | Computes the Init-Data digest itself, and writes the Operator Policy plus the generated KBS config, resource policy and RVPS values |
| `approve --endpoint URL --policy DIR --share-file my.share [--kbs-binary PATH]` | Security Operator | Runs the §4 flow. Success means "Share accepted", not "Trustee running" |
| `status --endpoint URL` | Anyone | Prints the Bootstrap Helper's status |

- **Operator Verifier runtime:** the default is the digest-pinned Trustee KBS image, run with podman or docker as `-p 127.0.0.1:<port>`. `--kbs-binary` uses a natively installed `kbs` instead.
- **Attestation collateral** comes from Intel PCS or a PCCS, AMD KDS, or offline files, using Trustee's own settings.
- There is no interactive prompt. Running `approve` against a valid Operator Policy *is* the approval.
- The CLI never logs Shares, JWEs, tokens or evidence bodies.
- The CLI never reuses `~/.kube/coco-config.toml`'s `trustee_server`.

## 7. Kubernetes / CVM integration

- **One CoCo pod.** The `bootstrap-helper` init container comes first, then the Trustee main container. Both images are pinned by `@sha256`.
- **Init-Data.** The `aa.toml` and `cdh.toml` KBS URL is `http://127.0.0.1:<proxy port>`. The Kata Agent policy comes from genpolicy and pins:
  - the images;
  - the Bootstrap Helper's args, including `--manifest-sha256`;
  - the mounts;
  - denial of exec and of additional containers *(Phase 0: confirm the genpolicy defaults)*.
- **ConfigMaps** (untrusted): `ceremony.json` and the Sealed Bundle (or a Secret, if the platform requires it).
- **Config volume.** It is shared between the init and main containers and is a `emptyDir` with `medium: Memory`, which is a tmpfs inside the guest *(Phase 0: prove it is guest-side on every platform)*. Trustee mounts it read-only at its config path.
- **Services.** The Bootstrap Helper's port is exposed by its own Service, and Trustee's KBS port by another. Network policy is optional and is never a confidentiality boundary.
- **Platforms.** The core is platform-agnostic: bare-metal TDX and SNP, peer-pods, and Azure SNP/TDX vTPM. TPM (swtpm) is used for CI and dev. The only thing that makes an environment production is which TEE types an Operator Policy accepts. There are no build flags and no dev binary.

## 8. Repository layout

```text
go.mod
cmd/trustee-bootstrap/   # standalone CLI main
cmd/bootstrap-helper/    # helper main
pkg/cli/                 # Cobra tree (NewTrusteeBootstrapCmd)
pkg/ceremony/            # manifest, share files, split/combine, commitments
pkg/seal/                # age+tar seal/unseal, safe extraction
pkg/policy/              # Operator Policy build, Init-Data digest, rego/RVPS generation
pkg/verifier/            # Operator Verifier lifecycle (container or binary)
pkg/relay/               # framing; CLI-side client; helper-side server + guest proxy
pkg/helper/              # state machine, CDH client
deploy/examples/         # pod, Init-Data, ConfigMaps (non-secret samples)
test/e2e/                # kind + Kata + swtpm, end to end
```

## 9. Phases

### Phase 0 — spike (blocking)

- [ ] Pin Trustee, guest-components, Kata, genpolicy, and CAA for peer-pods.
- [ ] Get the Kata + swtpm TPM attester running in a CI runner with KVM. Confirm what Trustee's TPM verifier requires (AK/EK trust) and that the Init-Data digest appears in its claims.
- [ ] Run stock CDH `get_resource` through a guest-loopback proxy and a WebSocket relay to a local `insecure_http` KBS with a benign resource, using a resource policy keyed on the Init-Data digest.
- [ ] Confirm genpolicy pins the Bootstrap Helper's args and denies exec in the generated policy.
- [ ] Confirm `medium: Memory` `emptyDir` is guest-side tmpfs and survives the init-to-main handoff (Kata bare metal and peer-pods).
- [ ] Confirm the KBS container image runs on Linux and WSL with `127.0.0.1` port publishing.

**Stop/escalate** if any item fails. Write up the blocker and the smallest upstream change. Never fall back to self-reported evidence, a plaintext share POST, or a host-visible volume.

### Phase 1 — formats and components (no VM)

- [ ] `pkg/ceremony`, `pkg/seal`, `pkg/policy` and their commands, with unit tests, including every negative case in §10.
- [ ] `pkg/relay` with limit, disconnect and framing tests.
- [ ] `pkg/helper` state machine against a fake CDH.

### Phase 2 — end to end on TPM (CI)

- [ ] kind + Kata + swtpm: two Security Operators unlock a 2-of-3 Trustee CVM. Trustee starts, then attests a separate workload that pins its certificate.
- [ ] All §10 tests that need no real TEE run in CI on every PR.

### Phase 3 — release gate (real TEE) and hardening

- [ ] Repeat Phase 2 on at least one of TDX, SNP or Azure vTPM.
- [ ] Redacted audit events. Runbooks for the Unlock Ceremony, Trustee upgrades, and roster change by a fresh Key Ceremony.
- [ ] SBOM, dependency pinning, and no test-only flags on the production path.

## 10. Acceptance tests

| ID | Scenario | Expected |
|---|---|---|
| AT-01 | Existing `cococtl` commands | Unchanged |
| AT-02 | `approve` running | Only a `127.0.0.1` listener on the operator machine; all remote connections outbound |
| AT-03 | Genuine Trustee CVM, matching Operator Policy | Share released and accepted |
| AT-04 | Different image digest, weakened agent policy or other Init-Data | No release |
| AT-05 | Replayed evidence or substituted `tee-pubkey` | No release |
| AT-06 | Observer on host or relay | Cannot recover a Share |
| AT-07 | Same index delivered twice | Counted once |
| AT-08 | Share that does not match its commitment | Rejected; index reported |
| AT-09 | Host mounts its own bundle sealed to the recipient | Every Share rejected (digest mismatch); Trustee does not start |
| AT-10 | Host mounts an older, previously approved bundle | Rejected unless the operators' current policy approves that digest |
| AT-11 | Swapped `ceremony.json`, or `--manifest-sha256` dropped | Bootstrap Helper fails in LOCKED |
| AT-12 | 1 valid Share of 2-of-3 | Stays locked |
| AT-13 | 2 valid Shares of 2-of-3 | Unlocks; Trustee starts |
| AT-14 | Corrupt bundle; tar with `..`, absolute path, symlink, hardlink or device file; oversized bundle | FAILED; nothing published |
| AT-15 | Bootstrap Helper crash or restart | New `boot_id`; earlier Shares gone |
| AT-16 | Host reads the config volume | No plaintext (real-TEE release gate) |
| AT-17 | Workload pins Trustee's certificate and attests | Succeeds against the unlocked Trustee |
| AT-18 | `approve` exits (success, failure or signal) | No listener, container or Share temp file remains |
| AT-19 | Second concurrent relay | `409` |
| AT-20 | Relay idle, total-time, frame-size and connection-count limits | Enforced; relay closed |

## 11. Definition of done

Delivered:

- the Go module with the Bootstrap Helper and command tree;
- the `cococtl` mount PR;
- the example manifests and Init-Data;
- 2-of-3 test fixtures with no live keys;
- CI running all of §10 except AT-16, on swtpm;
- one real-TEE run that passes all of §10;
- security review notes covering the actual trust roots, measurements and residual risks.

Synthetic or TPM-only evidence never counts as security completion.

## 12. References

- Original proposal: `Trustee onboarding in enclave.md`
- RCAR: https://github.com/confidential-containers/trustee/blob/main/kbs/docs/kbs_attestation_protocol.md
- CoCo Init-Data: https://confidentialcontainers.org/docs/features/initdata/
- CDH get-resource: https://confidentialcontainers.org/docs/features/get-resource/
- `cococtl`: https://github.com/confidential-devhub/cococtl
- Vault Shamir: https://github.com/hashicorp/vault/tree/main/shamir
- age: https://github.com/FiloSottile/age
