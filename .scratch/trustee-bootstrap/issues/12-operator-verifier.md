# 12 Operator Verifier lifecycle

Status: open
Type: task
Blocked by: 05, 11

## What

`pkg/verifier/`: start and stop the Operator Verifier for one `approve` run.

- Default: the digest-pinned KBS image under podman or docker, published as `-p 127.0.0.1:<random port>`. Alternative: `--kbs-binary`.
- A `0700` tmpfs directory holds the generated config, the per-run signer key and certificate, the ephemeral admin key and the Share payload at `trustee-bootstrap/share/current`.
- Refuse to start a config with insecure token or admin settings.
- Tear everything down on success, failure and signals.

## Spec

`IMPLEMENTATION_SPEC.md` §4 step 2, §6 (runtime); ADR 0005.

## Done when

- [ ] AT-02 and AT-18 pass.
- [ ] The Operator Verifier side of AT-21 and AT-22 passes.
- [ ] the Go gate exits 0.
