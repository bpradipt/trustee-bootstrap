# Trustee Bootstrap

Unlocking a full Trustee that runs inside a confidential VM, so that no single party can configure or impersonate it and a quorum of security operators must independently verify it before it starts.

## People

**Security Operator**:
A person who holds exactly one Share and decides, after verifying the Trustee CVM, whether to release it.
_Avoid_: operator (alone), security admin, approver

**Infrastructure Operator**:
The person who deploys the Trustee CVM and produces the Sealed Bundle. Untrusted with respect to Shares.
_Avoid_: IO, cluster admin, operator (alone)

**Ceremony Authority**:
The party that runs the Key Ceremony and publishes the Ceremony Manifest.
_Avoid_: ceremony leader, security authority

## Ceremonies

**Key Ceremony**:
The one-time offline event that creates the bootstrap key pair, splits the private key into Shares and retires the original.
_Avoid_: offline ceremony, setup

**Unlock Ceremony**:
One round, per Trustee CVM boot, in which at least K Security Operators verify the Trustee CVM and release their Shares to it.
_Avoid_: bootstrap session, approval, unlock session

## Artifacts

**Share**:
One Shamir fragment of the bootstrap private key, identified by its share index.
_Avoid_: key share, operator share, secret share

**Share Commitment**:
The published hash of a Share, recorded per share index in the Ceremony Manifest, by which the Trustee CVM recognises a genuine Share.
_Avoid_: share hash, share signature

**Ceremony Manifest**:
The public record of a Key Ceremony: threshold, share indices, Share Commitments and the bootstrap public key. Trusted because the Trustee CVM's measurement pins its digest, not because it is signed.
_Avoid_: ceremony.json (that is its file name), ceremony config

**Sealed Bundle**:
Trustee's complete initial configuration and secrets, encrypted to the bootstrap public key.
_Avoid_: encrypted config, payload, ciphertext, bootstrap payload

**Approved Bundle**:
The one Sealed Bundle, identified by its digest, that a Security Operator has agreed to let the Trustee CVM unseal.
_Avoid_: generation, config version

**Operator Policy**:
A Security Operator's own local record of what they will release their Share to: accepted TEE types, reference measurements, Init-Data digest and the Approved Bundle.
_Avoid_: bootstrap policy, approved policy

## Components

**Trustee CVM**:
The confidential VM in which full Trustee will run once unlocked.
_Avoid_: target CVM, primary Trustee, Trustee pod

**Bootstrap Helper**:
The component inside the Trustee CVM that collects Shares, reconstructs the private key and unseals the Sealed Bundle before Trustee starts.
_Avoid_: init container (that is how it is deployed), helper

**Operator Verifier**:
The short-lived attestation verifier a Security Operator runs on their own workstation to appraise the Trustee CVM and release their Share.
_Avoid_: local verifier, lightweight Trustee, local KBS

## Attestation

**Bootstrap Attestation**:
A Security Operator's Operator Verifier appraising the Trustee CVM.
_Avoid_: first attestation

**Workload Attestation**:
The unlocked Trustee appraising other confidential workloads in normal service.
_Avoid_: second attestation, normal attestation
