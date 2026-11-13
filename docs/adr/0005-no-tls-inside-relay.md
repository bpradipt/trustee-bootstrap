# No TLS on the bootstrap relay, inner or outer

The Operator Verifier serves plain HTTP on 127.0.0.1, and the Bootstrap Helper serves plain HTTP/WebSocket. TLS from an Ingress or a LoadBalancer is allowed but is not a security boundary. This deviates from the pre-baseline draft spec's end-to-end inner TLS.

Every security property of the unlock is carried elsewhere:

- RCAR binds the nonce and `tee-pubkey` into hardware evidence.
- The Share is delivered as JWE to that key.
- Share Commitments reject forged Shares.
- The approved bundle digest travels inside the JWE.

## Why regular CoCo needs TLS and the relay doesn't

A workload's CDH reaches Trustee over TLS, with Trustee's certificate in `kbs_cert`. RCAR proves the guest to the KBS, and JWE hides the resource, but neither proves the KBS to the guest: anyone can encrypt to the TEE key. TLS is what stops an impostor KBS from handing a workload a key or a policy of its own ([EV-04](../evals/04-impostor-trustee.md)).

On the bootstrap relay, the Share payload is the Trustee CVM's only KBS-served input, and the Bootstrap Helper authenticates its content itself. The Share's hash must match a commitment in the Ceremony Manifest, whose digest Init-Data measures (ADR 0003, ADR 0007). An impostor KBS can't produce a Share the helper accepts.

## What a relay holder can do

A party that holds the relay or the network can:

- read the evidence, the Init-Data, the nonces, the attestation tokens, `status` and timing;
- drop the relay, or forge `status` and the relay's close code. `approve` then prints `accepted` for a Share the helper never accepted, or fails for one it did (`pkg/helper/api.go`);
- route one `approve` run's Share to a second CVM that runs the same approved Init-Data ([EV-02](../evals/02-host-splices-one-approval.md), a residual risk in `SECURITY_THREAT_MODEL.md`).

It can't read or forge a Share, deliver one to a CVM whose Init-Data no Security Operator approved, or make the helper unseal a bundle they didn't approve.

## Why no TLS design pays off today

- **Inner TLS from the CDH to the Operator Verifier.** It needs a bootstrap CA as Init-Data's single `kbs_cert`, and a leaf certificate with an IP SAN for 127.0.0.1 for each Security Operator. It adds confidentiality for the RCAR messages, and nothing the unlock depends on. Even that confidentiality fails against a compromised Security Operator: their own leaf, with the host's relay, lets them sit in the middle of another operator's session. `status` and the close code stay outside the tunnel, and each approved copy trusts the same CA, so EV-02 stands.
- **TLS ended at the Bootstrap Helper.** It could authenticate `status` and the close code, but only with a key the operator can verify, and none exists before the unlock. A key in Init-Data or in the helper image is visible to the host, a key in the Sealed Bundle is what the Shares unlock, and a key the helper generates names nothing. Binding a helper key into the evidence needs a CDH/AA interface that the pinned guest-components lack (ADR 0003). Verifying it with our own code would break spec §0 requirement 1.
- **Mutual TLS, to stop the relay holder from sending its own requests to the Operator Verifier.** It needs a client key in the CVM, with the same gap. The hardened Operator Verifier config stays the control (AT-21, AT-22).

## When to revisit

- The Trustee CVM gets another KBS-served input whose value could change what runs or how it is configured. That input needs TLS or a measured digest. Image keys, image policies and registry credentials don't count: the agent policy pins each image's digest, so a fake one only fails the pull.
- Upstream guest-components gains a supported way to bind a TLS key into the evidence. Helper-ended TLS could then authenticate `status` and the outcome.

**Amended 2026-11-13.** The first version said a man-in-the-middle can't redirect a Share, which EV-02 disproves, and that inner TLS adds no property, which overstated it. This version keeps the decision and states what the relay exposes.
