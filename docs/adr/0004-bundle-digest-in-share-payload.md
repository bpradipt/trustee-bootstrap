# Security Operators approve an exact Sealed Bundle digest

The bootstrap public key is public, so anyone, including a hostile host, can seal a well-formed bundle containing their own admin key, policies or TLS key. Public-key sealing gives confidentiality, not origin authenticity. Each Security Operator's policy therefore pins the SHA-256 of the approved Sealed Bundle, and their share resource carries `{share_index, share, bundle_digest}`. The Bootstrap Helper unseals only a bundle whose digest equals the one sent by all K accepted Shares.

The host cannot forge that payload. It would need a genuine Share, which is checked against the Share Commitment, and it cannot alter the payload because the payload travels as JWE to the attested TEE key. This replaces the spec's `generation` field as both the authenticity and the rollback control: an older bundle simply has an unapproved digest.

## Considered Options

- Pin the bundle digest in Init-Data: rejected because every config change would then also change the pod spec and every operator's measurement reference.
- A signed bundle manifest with an Infrastructure Operator signing key: rejected because it adds a key, and the Infrastructure Operator is not the party whose approval matters.
