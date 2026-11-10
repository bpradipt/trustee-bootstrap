# Share Commitments replace per-operator signing keys

The Ceremony Manifest records SHA-256 of each Share per share index. The Bootstrap Helper accepts a Share only if its hash matches its index's commitment. This replaces the pre-baseline draft spec's per-operator signing key, signed share envelope, approval nonce and signed relay challenge.

The signing key added no confidentiality or threshold property:

- A forged Share only yields a wrong key, which the authenticated decryption rejects.
- A replayed share resource can't be decrypted by a new boot, because the JWE targets that boot's ephemeral TEE key.
- `boot_id` cannot be bound into attestation runtime-data through the CDH, so it was never a security binding.

Share Commitments also identify exactly which index was bad, which the signatures did not. Consequences: there is one fewer secret per Security Operator; relay admission is unauthenticated (squatting the relay is a DoS, which is out of scope); and `boot_id` is only a correlation ID.

This depends on the Ceremony Manifest itself being authentic inside the Trustee CVM. Otherwise an attacker could ship a manifest with their own commitments and threshold 1.
