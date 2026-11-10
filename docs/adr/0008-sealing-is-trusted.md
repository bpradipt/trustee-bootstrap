# Sealing is a trusted step

The Infrastructure Operator writes Trustee's plaintext config, including Trustee's TLS private key and every resource secret, and seals it. Whoever holds that plaintext can impersonate Trustee and read every secret it will serve. So the K-of-N quorum protects Trustee from the host, Kubernetes and fewer than K Security Operators. It doesn't protect Trustee from the person who authored its config.

We trust the sealing step: the Infrastructure Operator seals on a controlled machine and destroys the plaintext afterwards, following the runbook. The original proposal already had the Infrastructure Operator encrypt the config.

## Considered Options

- Generate Trustee's TLS key inside the CVM at unlock: rejected for v1. Workloads would need an attested certificate-issuance step to learn the certificate in advance, and resource secrets would still pass through the sealer.
- A separate Config Author role sealing in a clean room: the same trust model with a stricter separation of people. Organisations can adopt it without any design change.
