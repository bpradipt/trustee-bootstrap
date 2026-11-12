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

**Status:** in-progress

**Spec:** §1 (how workloads trust Trustee), §3 item 4 (sealed-config checks), §10 AT-27; ADR 0008.

- [ ] AT-27 covers the new violations: `seal` refuses each one, and the helper refuses the same tree sealed with stock `age`.
- [ ] The example Trustee config, and every tree the e2e tests seal, still pass.
- [ ] EV-07 passes: `seal` refuses a public name, a public IP and a CA certificate.
- [ ] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments
