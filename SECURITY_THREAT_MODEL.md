# Trustee-in-CVM: Security Summary and Threat Model

**Version:** v1.0 (baseline) | **Date:** 2026-11-10  
**Companions:** `IMPLEMENTATION_SPEC.md`, `GLOSSARY.md`, `docs/adr/`

## Security summary

**Objective.** Full Trustee's configuration and identity stay locked inside its Trustee CVM until K distinct Security Operators have each independently appraised that CVM. This holds even when the Kubernetes infrastructure is hostile.

**Core design.**

1. A Key Ceremony splits an age private key into K-of-N Shares and publishes a Ceremony Manifest containing Share Commitments.
2. The Infrastructure Operator seals Trustee's whole config, including Trustee's TLS key, to the matching public key.
3. The Trustee CVM's Init-Data pins:
   - the Bootstrap Helper and Trustee images;
   - the Kata Agent policy;
   - the Ceremony Manifest digest.
   The TEE evidence carries the Init-Data digest.
4. Each Security Operator's Operator Verifier, a stock Trustee KBS on `127.0.0.1` reached through an outbound relay, appraises that evidence. It then releases `{share, bundle_sha256}` as JWE to the attested TEE key.
5. The Bootstrap Helper accepts only Shares that match their commitment and that name the mounted bundle. After K of them, it unseals into guest memory and exits. Unmodified Trustee starts.

**Security claim (conditional).** An attacker controlling the host, the network, the storage and up to K−1 Security Operators cannot do any of the following:

- recover the bootstrap private key;
- cause a non-approved CVM to receive K Shares;
- cause an approved CVM to run a config that the K Security Operators did not approve;
- present Trustee's identity to workloads.

The claim depends on seven conditions:

1. TEE isolation holds.
2. The approved Init-Data and agent policy really do constrain the pod: images, args, no exec, and memory-backed state volume.
3. RCAR's binding of `tee-pubkey` and JWE delivery are enforced by the unmodified upstream code.
4. Each Security Operator builds their Operator Policy from a reviewed Init-Data and the correct Approved Bundle digest.
5. The Ceremony Authority destroyed the private key.
6. Workloads carry Trustee's certificate in their Init-Data, and that certificate names a cluster-internal host or private IP.
7. The Infrastructure Operator seals on a controlled machine and destroys the plaintext afterwards (ADR 0008).

## Assets

| Asset | Where it lives | Requirement |
|---|---|---|
| Bootstrap private key | Ceremony machine, briefly; Trustee CVM memory during unseal | Never stored in clear anywhere after the Key Ceremony |
| Share | One Security Operator's workstation; JWE in transit; CVM memory | Released only after a successful appraisal |
| Ceremony Manifest | Untrusted ConfigMap | Integrity only, through the digest pinned in Init-Data |
| Sealed Bundle | Untrusted ConfigMap or Secret | Confidential under age; authentic only through the Approved Bundle digest |
| Plaintext config, including Trustee's TLS key | Sealing machine until sealed; then Trustee CVM tmpfs | Destroyed on the sealing machine after `seal`; never host-visible; only the helper and Trustee can access it in the CVM |
| TEE key (`tee-pubkey` and its private key) | CDH/AA in the CVM | Bound to the evidence by RCAR runtime-data |
| Operator Policy | Security Operator's workstation | Built by the operator, never taken from the CVM or the host |

## Threat actors

**In scope:**

- a compromised Kubernetes admin, host, network or storage;
- other tenants;
- up to K−1 Security Operators;
- replay and rollback;
- spoofed evidence or keys;
- substituted images, config, bundles or manifests;
- malicious relays;
- crashes and partial state.

**Assumed trusted:**

- TEE hardware roots and a TCB that is not in debug mode;
- the Kata guest and agent-policy enforcement;
- the Ceremony Authority during the Key Ceremony;
- the Infrastructure Operator and their sealing machine. They see Trustee's TLS key and every resource secret, and must destroy that plaintext after sealing (ADR 0008);
- each Security Operator's own workstation.

**Out of scope:**

- DoS, including squatting on the single relay;
- compromise of the approved guest or of Trustee itself;
- TEE side channels and physical attacks;
- collusion of K Security Operators;
- runtime clients of the unlocked Trustee (governed by Trustee's own policies).

## Threats and mitigations

| Threat | Mitigation | Test |
|---|---|---|
| A fake or modified CVM requests Shares | Operator Verifier resource policy requires an accepted TEE type, the expected Init-Data digest, matching reference values and debug off | AT-04 |
| `tee-pubkey` substitution or evidence replay | Upstream RCAR binds the nonce and key into the evidence | AT-05 |
| **Relay holder forges an attestation token** naming its own TEE key | The Operator Verifier runs with `insecure_header_jwk = false` and trusts only the certificate of the signer the CLI generated for this run. The CLI refuses a config with that flag set | AT-21, AT-03 |
| **Unlocked Trustee accepts forged tokens or unauthenticated admin calls**, because its sealed KBS config came from upstream's sample | `seal` and the Bootstrap Helper both run the sealed-config checks (spec §3): no insecure flags, a configured signer whose certificate KBS trusts | AT-21, AT-22, AT-27 |
| Generic Init-Data or debug check rejects valid evidence, or accepts evidence missing a claim | One claim profile per TEE type; a missing required claim means deny | AT-28 |
| Helper crash after publication forces a pointless new ceremony, or leaves a half-published tree | The completion marker goes into the staging tree before the atomic rename, so the rename is the single commit point. On start the helper exits 0 if the marked tree exists and wipes staging otherwise | AT-15, AT-26 |
| Relay holder rewrites the Operator Verifier's resource policy through the admin API | Admin calls need the ephemeral admin key, which the CLI discards. The CLI refuses `InsecureAllowAll` | AT-22 |
| Host reads the Share in transit | JWE to the attested TEE key. There is no TLS by design (ADR 0005); TLS would protect nothing further | AT-06 |
| Forged Share | Share Commitment check identifies the bad index | AT-08 |
| **Host seals its own bundle to the public recipient** | The Approved Bundle digest travels inside each JWE share payload, and the Bootstrap Helper rejects a mismatch (ADR 0004) | AT-09 |
| **Host swaps the bundle or manifest after the helper checks it** | The Bootstrap Helper reads each file into memory once, in LOCKED, and hashes and decrypts only those bytes | AT-23 |
| Bundle rollback | On a fresh boot, an older digest is not in the operators' current Operator Policy. Within one boot, a Share already released stays valid (residual risk) | AT-10 |
| **Host swaps the Ceremony Manifest** (its own commitments, threshold 1) | The manifest digest is pinned in the Bootstrap Helper's args through the agent policy in Init-Data. A missing arg is fatal (ADR 0007) | AT-11 |
| One operator acting as many | One Share per index; there are K distinct commitments | AT-07 |
| Relay used to reach other local services | The CLI dials only its own Operator Verifier port and never an address from a frame. Limits and cleanup apply | AT-19, AT-20 |
| Host reads unlocked config | `medium: Memory` `emptyDir` (guest tmpfs) owned by Trustee's UID, no exec by agent policy | AT-16 |
| **Unlocked Trustee runs its built-in default policy**, which releases every resource to any attested non-sample TEE | The sealed config points the KBS storage backend at the published tree, and the sealed-config checks require the resource policy at its exact key; sessions stay in memory | AT-24, AT-27 |
| Operators can't reach the helper (Service routes only to Ready pods) | The helper's Service sets `publishNotReadyAddresses: true` | AT-25 |
| Trustee replaced after unlock | Image digests and container set pinned by agent policy | AT-04 |
| Partial or corrupt unseal | Authenticated age decryption, safe tar extraction, atomic rename, fail closed | AT-14 |
| An impostor serves workloads as Trustee | Once the sealing machine destroys its plaintext, Trustee's TLS key exists only in the Sealed Bundle, and workloads add its certificate as a trust root. Its certificate names a cluster-internal host or private IP, so no public CA will issue a competing one. `seal` and the Bootstrap Helper refuse a certificate that names any other host (sealed-config check 4) | AT-17, AT-27 |

## Security invariants

1. **No Share before attestation:** the Operator Verifier serves nothing until the EAR claims match the Operator Policy.
2. **No key substitution:** the JWE goes only to the `tee-pubkey` bound in the RCAR evidence.
3. **Only genuine Shares:** every accepted Share matches its commitment, and its index is unique.
4. **Only the Approved Bundle:** nothing is unsealed unless K accepted Shares name that exact bundle digest, and the helper decrypts the same in-memory bytes it hashed.
5. **Measured manifest:** the Ceremony Manifest is used only if its digest equals the measured args value.
6. **No host plaintext:** the key, Shares and config never leave CVM memory, apart from each operator's own Share at that operator.
7. **No partial start:** Trustee starts only after a complete, atomic publish.
8. **Fresh boot, fresh ceremony:** accepted Shares are never persisted, and a restart means a new Unlock Ceremony.
9. **Identity follows approval:** after sealing, only an approved Trustee CVM holds Trustee's TLS key. The sealing machine held it before then and is trusted to have destroyed it (ADR 0008). This protects workloads only while no other trusted CA can certify Trustee's host name (see residual risks).
10. **Only genuine tokens:** the Operator Verifier accepts only attestation tokens signed by its own AS key.

## Residual risks

- **Init-Data is the single root.** A wrong or weak Init-Data, such as an agent policy that allows exec or an unpinned arg, defeats everything. Operators must review it, not just hash it.
- **Agent policy lets the host drop pinned values** (it cannot change them). The Bootstrap Helper must treat a missing flag as fatal. This is tested.
- **Plain HTTP relay.** Evidence, Init-Data plaintext, tokens and status are visible to network observers. None of them is secret, but this is metadata exposure.
- **`kbs_cert` adds a root; it doesn't pin.** Workload guests keep their system CAs. If a guest trusts a CA that will certify Trustee's host name, that CA's customer can impersonate Trustee and serve workloads fake resources, though it can't obtain their secrets. A cluster-internal name or private IP limits this to private CAs in the guest image. `seal` and the Bootstrap Helper refuse a certificate that names anything else (ticket 18).
- **Upstream sample configs are unsafe here.** Trustee's sample KBS config enables `insecure_header_jwk` and `InsecureAllowAll`. The CLI must generate its own config and reject both.
- **The Infrastructure Operator sees the plaintext config.** A copy kept after sealing lets them impersonate Trustee and read every resource it serves. The quorum can't detect this; only the sealing runbook guards against it (ADR 0008).
- **Claim profiles cover only what was tested.** A TEE type whose profile has never passed a real-TEE run may accept wrong evidence. Production Operator Policies accept only tested profiles.
- **Released Shares are irrevocable for a live boot.** If Alice releases her Share for bundle A and later approves only B, the host can keep that CVM collecting. A compromised Bob then completes the unlock of A. Alice withdraws only by getting the CVM restarted. `--deadline` limits this in the honest case, but the host influences the guest clock.
- **An approval covers a configuration, not one VM.** An Operator Policy names an Init-Data digest, reference values and a bundle digest, and nothing in the TEE evidence identifies one instance. A host that holds the relay can start several identical Trustee CVMs and pass each of them the Share from one `approve` run: up to four, because a relay carries eight inner connections and each RCAR uses two. Every copy runs approved code with the Approved Bundle, so the claims above hold. Security Operators can't count the unlocked Trustees, though, and a copy can outlive the instance they retire. Binding an approval to one VM needs instance-unique data in the evidence, which upstream doesn't provide. EV-02 tests this.
- **Availability.** Every pod recreation needs K Security Operators, with a single replica and no HA (ADR 0002). Runtime KBS admin writes survive a Trustee container restart but are lost when the pod or the CVM is recreated.
- **Roster change** requires a full new Key Ceremony, a re-seal, new Init-Data and new Operator Policies.
- **TPM/swtpm** environments give no confidentiality. Only Operator Policies keep them out of production.
- Bugs in the trusted guest or in Trustee, TCB collateral errors, and collusion of K operators.

## Go/no-go

Do not unlock a Trustee holding production secrets until a real-TEE run proves all four of these:

- (a) image, policy and manifest binding through Init-Data;
- (b) RCAR/JWE share release over the relay;
- (c) threshold, commitment and bundle-digest rejection behaviour;
- (d) the guest-tmpfs handoff from init container to main container.

All four block the release. Passing CI on swtpm is necessary, but it is not sufficient.
