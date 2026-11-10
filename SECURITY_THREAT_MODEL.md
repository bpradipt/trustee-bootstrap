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

The claim depends on six conditions:

1. TEE isolation holds.
2. The approved Init-Data and agent policy really do constrain the pod: images, args, no exec, and memory-backed config volume.
3. RCAR's binding of `tee-pubkey` and JWE delivery are enforced by the unmodified upstream code.
4. Each Security Operator builds their Operator Policy from a reviewed Init-Data and the correct Approved Bundle digest.
5. The Ceremony Authority destroyed the private key.
6. Workloads pin Trustee's certificate in their Init-Data.

## Assets

| Asset | Where it lives | Requirement |
|---|---|---|
| Bootstrap private key | Ceremony machine, briefly; Trustee CVM memory during unseal | Never stored in clear anywhere after the Key Ceremony |
| Share | One Security Operator's workstation; JWE in transit; CVM memory | Released only after a successful appraisal |
| Ceremony Manifest | Untrusted ConfigMap | Integrity only, through the digest pinned in Init-Data |
| Sealed Bundle | Untrusted ConfigMap or Secret | Confidential under age; authentic only through the Approved Bundle digest |
| Plaintext config, including Trustee's TLS key | Trustee CVM tmpfs | Never host-visible; Trustee gets read-only access |
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
- the Infrastructure Operator's authoring of the plaintext config, since they see it by design;
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
| Host reads the Share in transit | JWE to the attested TEE key. There is no TLS by design (ADR 0005); TLS would protect nothing further | AT-06 |
| Forged Share | Share Commitment check identifies the bad index | AT-08 |
| **Host seals its own bundle to the public recipient** | The Approved Bundle digest travels inside each JWE share payload, and the Bootstrap Helper rejects a mismatch (ADR 0004) | AT-09 |
| Bundle rollback | An older digest is not in the operators' current Operator Policy | AT-10 |
| **Host swaps the Ceremony Manifest** (its own commitments, threshold 1) | The manifest digest is pinned in the Bootstrap Helper's args through the agent policy in Init-Data. A missing arg is fatal (ADR 0007) | AT-11 |
| One operator acting as many | One Share per index; there are K distinct commitments | AT-07 |
| Relay used to reach other local services | The CLI dials only its own Operator Verifier port and never an address from a frame. Limits and cleanup apply | AT-19, AT-20 |
| Host reads unlocked config | `medium: Memory` `emptyDir` (guest tmpfs), read-only mount, no exec by agent policy | AT-16 |
| Trustee replaced after unlock | Image digests and container set pinned by agent policy | AT-04 |
| Partial or corrupt unseal | Authenticated age decryption, safe tar extraction, atomic rename, fail closed | AT-14 |
| An impostor serves workloads as Trustee | Trustee's TLS key exists only in the Sealed Bundle, and workloads pin its certificate | AT-17 |

## Security invariants

1. **No Share before attestation:** the Operator Verifier serves nothing until the EAR claims match the Operator Policy.
2. **No key substitution:** the JWE goes only to the `tee-pubkey` bound in the RCAR evidence.
3. **Only genuine Shares:** every accepted Share matches its commitment, and its index is unique.
4. **Only the Approved Bundle:** nothing is unsealed unless K accepted Shares name that exact bundle digest.
5. **Measured manifest:** the Ceremony Manifest is used only if its digest equals the measured args value.
6. **No host plaintext:** the key, Shares and config never leave CVM memory, apart from each operator's own Share at that operator.
7. **No partial start:** Trustee starts only after a complete, atomic publish.
8. **Fresh boot, fresh ceremony:** accepted Shares are never persisted, and a restart means a new Unlock Ceremony.
9. **Identity follows approval:** only an approved Trustee CVM holds Trustee's TLS key.

## Residual risks

- **Init-Data is the single root.** A wrong or weak Init-Data, such as an agent policy that allows exec or an unpinned arg, defeats everything. Operators must review it, not just hash it.
- **Agent policy lets the host drop pinned values** (it cannot change them). The Bootstrap Helper must treat a missing flag as fatal. This is tested.
- **Plain HTTP relay.** Evidence, Init-Data plaintext, tokens and status are visible to network observers. None of them is secret, but this is metadata exposure.
- **The Infrastructure Operator sees the plaintext config.** This is accepted by design.
- **Availability.** Every pod recreation needs K Security Operators, with a single replica and no HA (ADR 0002). Runtime KBS admin writes are lost on restart.
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
