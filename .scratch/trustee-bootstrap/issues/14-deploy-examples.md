# 14 Deployment examples

Status: open
Type: task
Blocked by: 04, 05, 10

## What

`deploy/examples/`: everything an Infrastructure Operator needs, with non-secret sample values.

- Pod: `bootstrap-helper` init container and Trustee main container, both `@sha256`-pinned; one memory `emptyDir` state volume owned by Trustee's UID.
- Init-Data: `aa.toml` and `cdh.toml` pointing at the guest proxy; genpolicy output pinning images and helper args.
- ConfigMaps for `ceremony.json` and the Sealed Bundle.
- Two Services: the helper's with `publishNotReadyAddresses: true` and a numeric `targetPort`; Trustee's KBS port as an ordinary Service.
- The helper container image build.

## Spec

`IMPLEMENTATION_SPEC.md` §7, §8.

## Done when

- [ ] The manifests apply cleanly in the ticket 02 environment.
- [ ] The helper image builds reproducibly from this repo.
