# 18: Check Trustee's TLS certificate when sealing

**What to build:** a fourth sealed-config check. `seal` and the Bootstrap Helper both refuse a Trustee config tree whose HTTPS certificate a workload can't safely pin as `kbs_cert`. The check reads the key and certificate that `[http_server]` names, and refuses:

- a key or certificate that is missing from the tree, or a pair that doesn't match;
- a CA certificate;
- a certificate that names no DNS name or IP address;
- a certificate that names any host outside the cluster: a DNS name not under `.svc`, `.local` or `.internal`, or an IP address that isn't private (RFC 1918 or IPv6 ULA).

Like the other checks, its errors name the problem and never quote a value from the tree (spec §0 requirement 6).

**Why:** workloads trust Trustee through `kbs_cert` in their Init-Data, but the guest keeps its system CAs (spec §1; residual risk *"`kbs_cert` adds a root"*). Say Trustee's certificate names a public host. Anyone who gets a public CA certificate for that name can then impersonate Trustee to workloads. They can't obtain workload secrets, but they can serve fake resources. The security claim lists a cluster-internal name as its condition 6, and today only the seal runbook's witness enforces it. `pkg/seal` reads no certificate.

The quorum can't catch this mistake. Security Operators approve a Sealed Bundle by its digest and never see inside it, and the `tls.crt` that workload owners receive comes from the same Infrastructure Operator. The other three sealed-config checks exist for the same reason. The helper repeats them inside the CVM because a bundle sealed with stock `age` skipped them.

A CA certificate fails in another way: rustls in the guest refuses it as a server certificate. Every workload then fails to connect, and the Security Operators find out only after an unlock that needed K of them.

[EV-07](../evals/07-seal-with-public-certificate.md) found the gap.

**Decided:**

- Fail closed at the edges.
  - A custom cluster domain under a public name, such as `svc.k8s.example.com`, is refused. That is correct, because a public CA could certify it.
  - A private TLD such as `.corp`, and ClusterIPs in CGNAT space (`100.64.0.0/10`), are refused too. Use a `.internal` name or a private IP instead.
  - An override can come later if a real cluster needs one.
- Use the Go standard library only.
- Out of scope: expiry and key usage. Trustee and the workloads' TLS stack enforce both.

**Blocked by:** none

**Status:** done

**Spec:** §1 (how workloads trust Trustee), §3 item 4 (sealed-config checks), §10 AT-27; ADR 0008.

- [x] AT-27 covers the new violations: `seal` refuses each one, and the helper refuses the same tree sealed with stock `age`.
- [x] The example Trustee config, and every tree the e2e tests seal, still pass.
- [x] EV-07 passes: `seal` refuses a public name, a public IP and a CA certificate.
- [x] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments

- **The check.** `checkTLS` in `pkg/verifier/config.go` is check 4 of `CheckSealedConfig`, so `seal` and the helper run it next to checks 1 to 3.
  - It reads the files that `[http_server] private_key` and `certificate` name through `readInTree`. A path outside the sealed tree fails the same way the AS signer's does.
  - `tls.X509KeyPair` proves that the pair matches and parses the leaf.
  - The leaf must not be a CA, and it must carry a DNS name or an IP address. Every DNS name must end in `.svc`, `.local` or `.internal`, and every IP address must be private (`net.IP.IsPrivate`).
  - The errors are fixed strings. The AT-27 test checks that none of them quotes a name, an address, a path or PEM data from the tree.
- **Edges.** `TestSealedConfigChecksAllowOnlyClusterInternalTLSNames` pins them down.
  - Accepted: a Service name, `cluster.local`, `.internal`, RFC 1918 and IPv6 ULA addresses.
  - Refused: a cluster domain under a public name, `.corp`, CGNAT, a public IPv6 address, and one public name or address mixed in with internal ones.
  - DNS names are compared as written, so a name that differs only in case fails closed.
- **Fixtures.** `trusteetest.Tree` now writes a real ECDSA P-256 pair for `trustee.default.svc.cluster.local`, and `Violations` gains seven entries: missing key, missing certificate, mismatched key, CA, no names, public DNS name, public IP.
  - The entries run in `pkg/verifier`, in `seal` (`pkg/cli`) and on the helper's stock-`age` path (`pkg/helper`).
  - The fixture sets no validity period. Gremlins showed that nothing checks one, so the dates were untested code.
- **e2e.** The scripts share a `tls_pair` helper in `kind-kata-swtpm.sh`. `share-release.sh` needed it, because its placeholder tree had no TLS pair and `seal` would now refuse it.
- **Evidence.** Everything ran on the scratch VM (kind + Kata 4.2.0 + swtpm), with this work on top of `evals` at `5a7e7cb`:
  - `ci.sh go`: exit 0.
  - `ci.sh lint evals`: exit 0. golangci-lint reports 0 issues, gremlins kills 9 mutants with 0 lived and 0 not covered, and jscpd finds no clones.
  - `share-release.sh` PASS, `trustee-cvm.sh` PASS, `golden-path.sh` PASS.
- **EV-07.** On the VM, `seal` from this tree sealed the control tree (a leaf for `trustee.default.svc.cluster.local`). It refused `DNS:trustee.example.com`, `IP:8.8.8.8` and `CA:TRUE`, and wrote no bundle for any of them.
- **Found on the way.**
  - `golden-path.sh` selected events by pod name. Run right after `trustee-cvm.sh`, it saw the policy-blocked events of that script's tampered pod, which has the same name, and failed. It now selects by pod UID; that fix is a separate commit.
  - The VM's disk filled with dangling builder images from repeated `--no-cache` helper builds. `podman image prune` freed 3.9 GB.
