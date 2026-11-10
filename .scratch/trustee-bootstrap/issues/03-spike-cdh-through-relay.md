# 03 Spike: stock CDH get_resource through a relay

Status: open
Type: spike
Blocked by: 02

## What

Prove the core transport with throwaway code before writing the real thing. Inside a Kata pod, a container calls `GET http://127.0.0.1:8006/cdh/resource/<path>`. The CDH/AA, configured by Init-Data to use a guest-loopback proxy as their KBS URL, run RCAR through that proxy, a WebSocket relay that the laptop opens outbound, and on to a local KBS bound to `127.0.0.1`. The KBS serves a benign resource behind a resource policy keyed on the Init-Data digest.

## Spec

`IMPLEMENTATION_SPEC.md` §4 (flow and framing), §9 Phase 0; ADR 0005 (plain HTTP).

## Done when

- [ ] The benign resource reaches the container through the relay, with no listener on the laptop reachable from outside.
- [ ] The local KBS releases it only when the Init-Data digest matches; a changed Init-Data gets a deny.
- [ ] Findings that affect tickets 09 and 10 (connection counts per RCAR, reconnect behaviour, timing) are written into those tickets' Comments.
