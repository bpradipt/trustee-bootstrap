# EV-01: Host swaps the Sealed Bundle in a live pod

**Category:** hostile host
**Runs on:** kind + swtpm; `test/e2e/evals.sh ev01`
**Covers:** claim "an approved CVM runs only a config the K Security Operators approved"; invariant 4; AT-09 and AT-23, which today run only in `pkg/helper` and `cmd/bootstrap-helper` tests; ADR 0004

## Setup

- A 2-of-3 Key Ceremony and an Approved Bundle A, deployed as `test/e2e/trustee-cvm.sh` does.
- A host bundle H, sealed with stock `age` to the same recipient. H passes the sealed-config checks, and its resource policy releases every resource.
- Alice and Bob each hold an Operator Policy that names A's digest.

## Action

1. **Swap before boot.** The host puts H in the `trustee-sealed-bundle` ConfigMap and starts the pod. Alice and Bob run `approve`.
2. **Swap after LOCKED.** Recreate the pod with A in the ConfigMap. When `status` reports `COLLECTING`, the host replaces the ConfigMap with H and waits for the kubelet to sync it (about 60 s). Alice and Bob run `approve`.

## Expected

Part 1:

- `status` lists both indices in `rejected`, and `accepted` stays `[]`.
- Each `approve` fails with `Share not accepted`.
- The helper never publishes, and the Trustee container never starts.

Part 2:

- Both Shares are accepted and the helper publishes A.
- `workload-ok` gets A's sealed resource, and `workload-other` stays refused under A's policy (the AT-24 probes).

## Notes

Part 2 proves something only if Kata copies a ConfigMap update into the guest. Check this first on a pod with no agent policy, as `check_tmpfs` does. If Kata never propagates the update, record that: part 2 then passes for the wrong reason, and AT-23 stays in-process only.

`evals.sh` runs that check with `bundle-probe`, a pod with no agent policy that mounts the same ConfigMap. On Kata 4.2.0 with swtpm, the swapped bundle reached the running guest within the wait. So the host can change the files under a running helper, and part 2 shows that the helper ignores the change: it unseals only the bytes it read in LOCKED.

## Results

- 2026-11-12, branch `evals-scripted` on `f629a3a`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals.sh`: **pass**.
  - Part 1: with the host's bundle mounted from boot, the helper rejected both Shares (`rejected: [1, 3]`), and Trustee never started.
  - Part 2: `bundle-probe` saw the swapped bundle inside its running guest. After the swap, Alice and Carol unlocked. `workload-ok` got the approved bundle's secret, and `workload-other` got `DENIED`, although the host's bundle allows every request.
