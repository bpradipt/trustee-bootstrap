# Everything lives here; cococtl only mounts the command tree

This repo holds a single Go module containing:

- the Bootstrap Helper;
- the full `trustee-bootstrap` Cobra command tree (`approve`, `status`, `policy build`, `seal`, `ceremony split`), exported as `NewTrusteeBootstrapCmd()`;
- the example manifests;
- the integration tests.

It also builds a standalone `trustee-bootstrap` binary, which is what goes to the air-gapped Key Ceremony machine. `cococtl` gets a roughly 5-line change that mounts the command tree, delivered as a fork or PR.

Reasons: `cococtl` describes itself as a dev/test utility, while this security-critical component needs its own review and release gate. A tiny upstream diff also keeps that PR reviewable.
