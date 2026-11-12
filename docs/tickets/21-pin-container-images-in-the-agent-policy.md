# 21: Pin container images in the Kata Agent policy

**What to build:** the Trustee CVM refuses to start a container whose image isn't the one its measured Init-Data names. Then a host that swaps the Bootstrap Helper's or Trustee's image in the pod spec gets no running container and no Share.

**Why:** the security claim depends on condition 2: "the approved Init-Data and agent policy really do constrain the pod: images, args, no exec". Spec §7 says genpolicy's agent policy pins the images, but with Kata 4.2.0 and guest pull it doesn't.

- **The rule.** Kata 4.2.0's `rules.rego` accepts an `image_guest_pull` storage without looking at the image it names. The rule reads `# TODO: missing validation for fields: driver_options, source`.
- **The annotations.** `allow_anno_key_value` accepts every `io.kubernetes.cri.*` annotation whatever its value, `io.kubernetes.cri.image-name` included.
- **The Init-Data.** Ours sets no `[image]` policy for CDH, so nothing in the guest checks the image at pull time either.
- **What did get verified.** Ticket 06 confirmed the policy pins the helper's args and denies exec. It never tried another image under the same Init-Data, and neither does AT-04, whose e2e check changes the Init-Data itself.

**The attack, observed** on the scratch VM (kind + Kata 4.2.0 + swtpm), 2026-11-12:

1. Deploy the approved Trustee CVM: Init-Data as reviewed, helper image `bootstrap-helper@sha256:93fd4780…`.
2. Build another image, `bootstrap-helper@sha256:d197df14…`: the same image plus one layer. Put it in the pod spec, and leave the `cc_init_data` annotation byte for byte the same.
3. The agent creates and starts the container. No event says "blocked by policy".
4. Alice runs `approve` with her unchanged Operator Policy. The evidence carries the approved Init-Data digest, so her Operator Verifier releases. The helper from the unapproved image accepts her Share: `accepted: [1]`.

A real attacker puts their own binary at the helper's entrypoint path, with the same args and env. CDH hands that binary each decrypted Share. With K of them the attacker rebuilds the private key, decrypts the Sealed Bundle (which the host holds), and holds Trustee's TLS key and every resource secret. Swapping the Trustee container's image the same way gives a malicious Trustee the unsealed config. That breaks claims 1, 3 and 4.

**Options to weigh:**

1. **Ship our own rule in the agent policy.** genpolicy embeds `rules.rego` in the Init-Data, so the policy is ours to extend, and Security Operators review it with the rest. The rule would check that an `image_guest_pull` storage's `source` (and `driver_options`, if the image name travels there) names exactly the image the policy data records with its digest. A digest pins content: the guest's image-rs checks what it pulls against it. This needs a look at what the agent receives in a guest-pull `CreateContainerRequest`.
2. **Upstream.** Report the TODO to Kata with this test, and check whether a newer genpolicy validates `source`. Moving the Kata pin also moves every Init-Data digest.
3. **Image signatures through CDH.** An `[image]` security policy in Init-Data, with signed images. This needs the policy and keys in the guest before the first pull, while the only KBS a CVM reaches before unlock is behind the relay.

Option 1 can ship without upstream changes.

**Blocked by:** none. This blocks any production unlock, alongside ticket 17.

**Status:** done

**Spec:** §7 (Init-Data and the Kata Agent policy); `SECURITY_THREAT_MODEL.md` condition 2, the threat "Trustee replaced after unlock", residual risk "Init-Data is the single root"; AT-04.

- [x] Under unchanged Init-Data, a helper or Trustee container from any other image never starts. The agent refuses it with a policy event.
- [x] Security Operators can read the new rule when they review the Init-Data, and the runbook's review step says what to look for.
- [x] An e2e check runs the swap above, for both containers, and fails if either starts.
- [x] Spec §7 and the threat model say what pins the images, and since which version.
- [x] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>`, `test/e2e/golden-path.sh` and `test/e2e/evals-cluster.sh ev09` exit 0.

## Comments

- **Found by EV-09, fault 2.** The eval put v1's helper digest into the v2 pod without running genpolicy again. It expected `CreateContainerRequest is blocked by policy` and saw no policy event at all. A test that swapped in an image with an extra layer under unchanged Init-Data then reproduced the full attack (steps above). Both runs used throwaway test keys, and the swapped image ran the real helper binary.
- **Option 1, shipped.** `deploy/genpolicy/rules.rego.patch` adds `trustee_bootstrap_allow_image` to Kata 4.2.0's `rules.rego`, called from `CreateContainerRequest`. With guest pull, a workload container's `io.kubernetes.cri.image-name` annotation, its `image_guest_pull` storage's `source`, and the image name in that storage's metadata must all equal the image genpolicy recorded, digest included. The sandbox container has no image and passes. `trustee-cvm.sh` and the runbook patch `rules.rego` before genpolicy, so the rule travels in the Init-Data that Security Operators review and the CVM measures.
- **No Kata change.** Decided 2026-11-12: the agent policy is a deployment-time choice. genpolicy's `rules.rego` is the deployer's to extend, so trustee-bootstrap keeps its rule as a patch and rechecks it when the Kata pin moves.
- **Verified** on the scratch VM (kind + Kata 4.2.0 + swtpm), 2026-11-12, branch `evals-rest`:
  - `test/e2e/trustee-cvm.sh`: PASS. Under the approved Init-Data, the helper from the approved image plus one layer got `CreateContainerRequest is blocked by policy` and never ran. With Trustee's image swapped the same way, Alice and Carol's Shares unlocked the helper, and the agent then refused the Trustee container. AT-13, AT-17, AT-24 and AT-26 still pass, so the rule accepts the approved images.
  - `test/e2e/golden-path.sh`: PASS.
  - `test/e2e/evals-cluster.sh ev09 ev05`: EV-09 passes, with fault 2 refused by policy. EV-05's new `upstream-rules` variant, Kata's rules without the patch, fails the runbook checklist's image-pinning line.
  - `test/e2e/ci.sh go` and `test/e2e/ci.sh lint origin/main` exit 0. No Go changed. Shellcheck is clean on `trustee-cvm.sh` and `evals-cluster.sh`.
