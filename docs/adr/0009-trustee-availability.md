# Keeping Trustee available: re-unlock each replica, or unlock from a peer

**Status:** undecided. [Ticket 24](../tickets/24-trustee-availability.md) tracks the decision.

ADR 0002 makes v1 a single Trustee CVM. Its config lives only in guest memory, so every pod recreation (node reboot, eviction, upgrade) needs K Security Operators, and Trustee serves nothing until they finish. We want several Trustee CVMs for availability: when one is lost, the others keep serving workloads while it comes back. Load balancing is a secondary goal.

Both options keep the Unlock Ceremony for the first replica, and for the case where every replica is lost at once.

## Common to both options

- Every replica unseals the same Sealed Bundle under the same Init-Data. So every replica serves the same TLS certificate, resources, policies and AS token signer, and a workload's `kbs_cert` works with any of them.
- The replicas run on different nodes, for example as a StatefulSet with pod anti-affinity and a PodDisruptionBudget.
- RCAR is a session held in one KBS instance's memory, so the `trustee` Service needs session affinity (`sessionAffinity: ClientIP`). The replicas share the token signer, so a bearer token from one should verify on another. Nobody has tested which credential the CDH sends.
- KBS admin writes stay unsupported (ADR 0002). With replicas they would also diverge.

## Option A: the quorum unlocks each replica

Each replica gets its own Bootstrap Helper endpoint, a Service for each pod in place of today's single `trustee-bootstrap-helper` Service, and its own Unlock Ceremony. With 3 replicas and K = 2, that is six `approve` runs. Each lost replica costs K more.

- **Code:** none in the helper or the CLI. The example pod, the runbooks and the e2e tests change.
- **Availability:** depends on how fast K Security Operators respond. Maintenance costs a ceremony for each replica it restarts.
- **Security claim:** unchanged. Each replica is one more copy that the quorum approved, the residual risk that EV-02 shows. A budget of one release per `approve` run, counted at the Operator Verifier, would cap the copies at the number of runs over K, with honest operators. That budget needs `approve` to see its Operator Verifier's releases, and spec §4 forbids parsing the relay's inner bytes.

## Option B: replicas unlock from a running replica

The quorum unlocks the first replica as today. Every later replica, and every restart, unlocks from a replica that runs:

1. The Sealed Bundle carries a resource policy that releases a replica payload only to the approved Init-Data, TEE type and reference values, with debug off. That is the appraisal an Operator Verifier makes.
2. After it unseals, the first replica's helper adds the replica payload to Trustee's resources: the bootstrap private key and the approved bundle digest.
3. A new replica's helper asks its CDH for that resource through the same guest proxy, pointed at a running replica's KBS. The URL is a helper argument, so Init-Data measures it. The payload arrives as a JWE to the new replica's TEE key.
4. The new replica accepts the key only if it derives the Ceremony Manifest's `recipient`. It unseals the mounted bundle only if its digest matches the payload's. The host lacks the key, so it can't fake a payload, and ADR 0005's reasoning holds.
5. If no replica answers, the helper collects Shares as today.

- **Code:** the helper gains the peer path and publishes the replica payload. The sealed-config checks gain a check of the replica-release policy.
- **Availability:** holds as long as one replica runs. Maintenance needs no ceremony.
- **Security claim:** changes in four ways.
  - The bootstrap private key lives in each replica's memory for that replica's lifetime. Today it exists there only during the unseal (`SECURITY_THREAT_MODEL.md`, Assets).
  - The quorum appraises the first replica only. Later replicas depend on the replica-release policy, which sits in the sealed config. Security Operators approve that config by digest but can't read it. A lax policy hands the bootstrap key to any TEE.
  - Nothing bounds the number of copies. The host can start any number of replicas with the approved Init-Data, and Trustee doesn't count releases.
  - A retired bundle lives as long as one of its replicas runs, and the host controls pod lifecycles. Each new bundle needs a new Trustee certificate, so that workloads move to the new `kbs_cert` and the old replicas serve no updated workload.

## Questions to settle

- **B:** who writes the replica-release policy, and how do Security Operators confirm it? The helper could generate it from values the CVM measures, in place of the Infrastructure Operator.
- **B:** send the bootstrap key, which the new replica checks against the measured `recipient`? Or the unsealed config tree, which it has no measured value to check against?
- **B:** is an unbounded copy count acceptable, given that each copy runs approved code in a TEE?
- **Both:** does the CDH send the session cookie or the bearer token with a resource request? The answer decides whether session affinity is enough.
- **A:** can `approve` count its Operator Verifier's releases without parsing the relay's inner bytes, for example from KBS's own log?
- **Both:** does the answer change once ADR 0002's v2 path, an external storage backend, exists?

## Deciding

Option A fits when K Security Operators can respond within the outage the service can stand, and replica restarts are rare. Option B fits when restarts are routine and its four changes to the security claim are acceptable. Put the chosen option through an adversarial review before any code. Then update ADR 0002, `SECURITY_THREAT_MODEL.md` and spec §5.
