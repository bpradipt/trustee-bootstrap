# EV-04: Impostor Trustee serves workloads

**Category:** hostile host
**Runs on:** kind + swtpm
**Covers:** claim "an attacker can't present Trustee's identity to workloads"; invariant 9; condition 6; residual risk "`kbs_cert` adds a root"; AT-17, which tests only the real Trustee

## Setup

- An unlocked Trustee and a workload pod whose Init-Data carries Trustee's `tls.crt` as `kbs_cert`, as `trustee-cvm.sh` sets up for AT-17.
- The host runs its own KBS in an ordinary pod, outside any CVM. It has a fresh self-signed leaf certificate for the same host name, a resource policy that allows every request, and a resource at the workload's path holding a value the host chose.
- The host points Trustee's KBS Service at the impostor by changing the Service's selector.

## Action

The workload starts, attests and fetches its resource.

## Expected

- The workload's TLS handshake with the impostor fails.
- The workload receives no resource, and the host's value never reaches it.
- When the Service points back at the real Trustee, a new workload pod gets the sealed resource.

## Notes

The guest keeps its system CAs. A certificate for Trustee's host name from a CA in the guest image would let the impostor through: that is the residual risk, and [EV-07](07-seal-with-public-certificate.md) tests the step that guards it.

## Results

None yet.
