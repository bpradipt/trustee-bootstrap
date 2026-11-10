# No TLS on the bootstrap relay, inner or outer

The Operator Verifier serves plain HTTP on 127.0.0.1, and the Bootstrap Helper serves plain HTTP/WebSocket. TLS from an Ingress, a LoadBalancer or port-forward is allowed but is not a security boundary. This deliberately deviates from the pre-baseline draft spec's end-to-end inner TLS.

Every security property is carried elsewhere:

- RCAR binds the nonce and `tee-pubkey` into hardware evidence.
- The Share is delivered as JWE to that key.
- Share Commitments reject forged Shares.
- The approved bundle digest travels inside the JWE.

A man-in-the-middle can read evidence and tokens, but it can't read, forge or redirect a Share. Keeping inner TLS would have needed a bootstrap CA, because Init-Data trusts exactly one KBS certificate. It would also have needed per-operator leaf certificates with an IP SAN for 127.0.0.1 and a certificate lifecycle, all for no added property. The Bootstrap Helper's own outer certificate can't be bound to attestation anyway.
