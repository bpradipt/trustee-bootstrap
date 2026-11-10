# 05 Default secure Trustee config

Status: open
Type: spike
Blocked by: 01

## What

Write the secure KBS + AS config that both the Operator Verifier and the unlocked Trustee start from, so nobody copies upstream's insecure sample. Decided after review: we ship this default rather than track every upstream option.

The config must:
- set `insecure_header_jwk = false` and `insecure_http = false` (the Operator Verifier is the one exception to `insecure_http`, see ADR 0005);
- require an admin key (never `InsecureAllowAll`);
- give the AS token broker a signer key and certificate, with KBS `trusted_certs_paths` listing that certificate;
- point `storage_backend` at the published tree and keep sessions in memory;
- carry a resource policy at the backend's exact policy key.

## Spec

`IMPLEMENTATION_SPEC.md` §3 (sealed-config checks), §4 step 2, §7 (state volume), §9 Phase 0; ADR 0002, ADR 0005.

## Done when

- [ ] Templates are committed: `deploy/config/operator-verifier/` and `deploy/config/trustee/`.
- [ ] The pinned KBS starts from each; a self-signed token is rejected; an admin call without the key is rejected.
- [ ] Unlocked Trustee serves the sealed policy and resources, not the built-in default; record the exact policy key for sealed-config check 3.
- [ ] A syntactically broken resource policy makes KBS deny every request.
- [ ] The KBS container runs on Linux and WSL with `-p 127.0.0.1:<port>`.
