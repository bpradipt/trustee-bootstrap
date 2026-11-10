# The Ceremony Manifest is measured, not signed

The SHA-256 of the Ceremony Manifest is passed in the Bootstrap Helper's container args. Kata Agent policy pins container args exactly, and that policy is part of Init-Data, whose digest is bound into the TEE evidence on every target platform:

- TDX: MRCONFIGID or RTMR3
- SNP: HOSTDATA
- Azure vTPM and TPM: PCR8

The manifest file itself arrives through an untrusted ConfigMap. The Bootstrap Helper refuses to start if the flag is missing (the policy lets the host drop pinned values, though not change them) or if the hash doesn't match. Security Operators verify the manifest implicitly when they verify the Init-Data digest.

This removes the pre-baseline draft spec's Ceremony Authority signing key and its separately anchored trust root.

## Considered Options

- Signed manifest with the authority key anchored in Init-Data: rejected because the args pin already gives integrity with no key to protect.
- Manifest as an extra Init-Data entry: rejected because containers cannot read extra entries, and peer-pods drops unknown entries.
- Pinning ConfigMap contents through genpolicy: rejected because genpolicy does not hash volume contents.

## Consequences

A new Key Ceremony changes Init-Data, and every Operator Policy must be rebuilt.
