# The Sealed Bundle is Trustee's entire state (v1)

Unlocked Trustee's configuration lives on a guest-private volume that does not survive pod recreation. In v1 the Sealed Bundle is therefore treated as Trustee's complete and only state. Any change to resources, policies or reference values means sealing a new bundle and running a new Unlock Ceremony. Writes made through the KBS admin API at runtime are ephemeral and unsupported.

## Considered Options

- Persistent encrypted volume keyed from the reconstructed private key: rejected for v1 because it adds key derivation, volume lifecycle and rollback concerns.
- External storage backend (for example Vault) with credentials carried in the bundle: the likely v2 path.

## Consequences

Every pod recreation (node reboot, eviction, upgrade) needs K Security Operators. v1 runs a single replica with a runbook; there is no HA.
