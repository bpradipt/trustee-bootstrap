#!/usr/bin/env python3
"""Generate the claim-profile fixtures in this directory (AT-28).

Each value comes from the Trustee v0.22.0 source formulas that
docs/claim-profiles.md cites, written here independently of pkg/policy:

  - tpm, az-snp-vtpm, az-tdx-vtpm: init_data is PCR8 = sha256(0^32 || digest)
    (deps/verifier/src/tpm/mod.rs, az_snp_vtpm/mod.rs verify_init_data).
  - tdx: init_data is MRCONFIGID, the digest padded with zeros to 48 bytes
    (tdx/mod.rs, lib.rs regularize_data).
  - snp: init_data is HOST_DATA, the digest itself (snp/mod.rs).
  - Claim names and types: each verifier's claim builder. EAR layout:
    attestation-service/src/ear_token/broker.rs transform_claims.

digest is sha256 of init-data.toml. Measurements are placeholders derived
from fixed seeds; no hardware produced any value.

Run from the repository root, then check that nothing changed:

  python3 -I test/e2e/profiles/testdata/gen.py test/e2e/profiles/testdata
  git diff --exit-code test/e2e/profiles/testdata
"""
import base64, hashlib, json, os, sys

out = sys.argv[1]
os.makedirs(out, exist_ok=True)

init_data = b'''version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = \'\'\'
[token_configs.kbs]
url = "http://127.0.0.1:8081"
\'\'\'
'''
open(os.path.join(out, "init-data.toml"), "wb").write(init_data)

digest = hashlib.sha256(init_data).digest()
other = hashlib.sha256(b"other Init-Data").digest()


def pcr8(d):  # tpm/mod.rs, az_snp_vtpm/mod.rs verify_init_data
    return hashlib.sha256(bytes(32) + d).hexdigest()


def mrconfigid(d):  # tdx/mod.rs regularize_data(.., 48, "MRCONFIGID")
    return (d + bytes(48 - len(d))).hex()


def h(seed, n):  # placeholder measurement of n bytes
    return hashlib.sha384(seed.encode()).digest()[:n] if n <= 48 else (hashlib.sha512(seed.encode()).digest()[:n])


def hx(seed, n):
    return h(seed, n).hex()


AK = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfixture"
rv = {
    "trusted_aks": [AK],
    "tpm_pcr11": [hx("tpm pcr11", 32)],
    "rtmr_1": [hx("rtmr_1", 48)],
    "rtmr_2": [hx("rtmr_2", 48)],
    "mr_td": [hx("mr_td", 48)],
    "xfam": ["e702060000000000"],
    "snp_launch_measurement": [hx("snp measurement", 48)],
    "snp_bootloader": [10],
    "snp_microcode": [213],
    "snp_snp_svn": [23],
    "snp_tee_svn": [0],
    "measurement": [base64.b64encode(h("az snp measurement", 48)).decode()],
    "snp_pcr11": [hx("az snp pcr11", 32)],
    "tcb_bootloader": ["10"],
    "tcb_microcode": ["213"],
    "tcb_snp": ["23"],
    "tcb_tee": ["0"],
    "smt_enabled": ["true"],
    "tsme_enabled": ["false"],
    "abi_major": ["0"],
    "abi_minor": ["31"],
    "single_socket": ["false"],
    "smt_allowed": ["true"],
    "tdx_pcr11": [hx("az tdx pcr11", 32)],
}
json.dump(rv, open(os.path.join(out, "reference-values.json"), "w"), indent=2)
open(os.path.join(out, "reference-values.json"), "a").write("\n")

# The P-256 base point: a valid TEE key for KBS to encrypt the fixture to.
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
tee_pubkey = {
    "kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A256KW",
    "x": b64u(bytes.fromhex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")),
    "y": b64u(bytes.fromhex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")),
}

EV = "/submods/cpu0/ear.veraison.annotated-evidence"


def token(tee, init, tee_claims, vector):
    return {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "submods": {"cpu0": {
            "ear.status": "affirming",
            "ear.trustworthiness-vector": vector,
            "ear.veraison.annotated-evidence": {
                "init_data": init,
                "init_data_claims": {"aa.toml": {"token_configs": {"kbs": {"url": "http://127.0.0.1:8081"}}}},
                "runtime_data_claims": {"tee-pubkey": tee_pubkey},
                tee: tee_claims,
            },
        }},
    }


def td_quote(rtmrs=True, mr_config_id=None):
    body = {"mr_td": rv["mr_td"][0], "xfam": rv["xfam"][0],
            "td_attributes": "0000001000000000",
            "mr_config_id": mr_config_id or "00" * 48}
    if rtmrs:
        body.update(rtmr_1=rv["rtmr_1"][0], rtmr_2=rv["rtmr_2"][0])
    return {"header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"}, "body": body}


td_attrs = {"debug": False, "septve_disable": True, "protection_keys": False, "key_locker": False, "perfmon": False}

fixtures = {}

fixtures["tpm"] = dict(
    source="deps/verifier/src/tpm/mod.rs parse_tee_evidence, extend_claim",
    claims=token("tpm", pcr8(digest),
                 {"ak_public": AK, "pcr08": pcr8(digest), "pcr11": rv["tpm_pcr11"][0]},
                 {"executables": 3, "hardware": 2}),
    deny={"wrong Init-Data": {EV + "/init_data": pcr8(other), EV + "/tpm/pcr08": pcr8(other)},
          "not affirming": {"/submods/cpu0/ear.status": "warning"},
          "untrusted AK": {EV + "/tpm/ak_public": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAother"}},
    required=["/submods/cpu0/ear.status", EV + "/init_data", EV + "/tpm/ak_public", EV + "/tpm/pcr11"],
)

tdx_init = mrconfigid(digest)
fixtures["tdx"] = dict(
    source="deps/verifier/src/tdx/claims.rs generate_parsed_claim",
    claims=token("tdx", tdx_init,
                 {"quote": td_quote(mr_config_id=tdx_init), "td_attributes": td_attrs, "tcb_status": "UpToDate"},
                 {"executables": 4, "hardware": 2, "configuration": 2}),
    deny={"wrong Init-Data": {EV + "/init_data": "00" * 48, EV + "/tdx/quote/body/mr_config_id": "00" * 48},
          "debug on": {EV + "/tdx/td_attributes/debug": True, EV + "/tdx/quote/body/td_attributes": "0100001000000000"},
          "not affirming": {"/submods/cpu0/ear.status": "warning"}},
    required=["/submods/cpu0/ear.status", EV + "/init_data", EV + "/tdx/td_attributes/debug",
              EV + "/tdx/quote/body/rtmr_1", EV + "/tdx/quote/body/rtmr_2", EV + "/tdx/quote/body/mr_td",
              EV + "/tdx/quote/body/xfam"],
)

snp = {
    "policy_abi_major": 0, "policy_abi_minor": 31, "policy_smt_allowed": True, "policy_migrate_ma": False,
    "policy_debug_allowed": False, "policy_single_socket": False,
    "reported_tcb_bootloader": 10, "reported_tcb_tee": 0, "reported_tcb_snp": 23, "reported_tcb_microcode": 213,
    "platform_tsme_enabled": False, "platform_smt_enabled": True,
    "measurement": rv["snp_launch_measurement"][0], "chip_id": hx("chip id", 64),
}
fixtures["snp"] = dict(
    source="deps/verifier/src/snp/mod.rs parse_tee_evidence",
    claims=token("snp", digest.hex(), snp, {"executables": 3, "hardware": 2, "configuration": 3}),
    deny={"wrong Init-Data": {EV + "/init_data": other.hex()},
          "debug on": {EV + "/snp/policy_debug_allowed": True},
          "not affirming": {"/submods/cpu0/ear.status": "warning"}},
    required=["/submods/cpu0/ear.status", EV + "/init_data", EV + "/snp/policy_debug_allowed",
              EV + "/snp/measurement", EV + "/snp/reported_tcb_bootloader", EV + "/snp/reported_tcb_microcode",
              EV + "/snp/reported_tcb_snp", EV + "/snp/reported_tcb_tee"],
)

az_snp = {
    "policy_abi_major": "0", "policy_abi_minor": "31", "policy_smt_allowed": "true", "policy_migrate_ma": "false",
    "policy_debug_allowed": "false", "policy_single_socket": "false",
    "reported_tcb_bootloader": "10", "reported_tcb_tee": "0", "reported_tcb_snp": "23",
    "reported_tcb_microcode": "213", "platform_tsme_enabled": "false", "platform_smt_enabled": "true",
    "measurement": rv["measurement"][0],
    "tpm": {"pcr08": pcr8(digest), "pcr11": rv["snp_pcr11"][0]},
}
AZS = EV + "/az-snp-vtpm"
fixtures["az-snp-vtpm"] = dict(
    source="deps/verifier/src/az_snp_vtpm/mod.rs parse_tee_evidence_az, extend_claim",
    claims=token("az-snp-vtpm", pcr8(digest), az_snp, {"executables": 3, "hardware": 2, "configuration": 2}),
    deny={"wrong Init-Data": {EV + "/init_data": pcr8(other), AZS + "/tpm/pcr08": pcr8(other)},
          "debug on": {AZS + "/policy_debug_allowed": "true"},
          "not affirming": {"/submods/cpu0/ear.status": "warning"}},
    required=["/submods/cpu0/ear.status", EV + "/init_data", AZS + "/policy_debug_allowed"] + [
        AZS + "/" + c for c in ["measurement", "tpm/pcr11", "reported_tcb_bootloader", "reported_tcb_microcode",
                                "reported_tcb_snp", "reported_tcb_tee", "platform_smt_enabled",
                                "platform_tsme_enabled", "policy_abi_major", "policy_abi_minor",
                                "policy_single_socket", "policy_smt_allowed"]],
)

AZT = EV + "/az-tdx-vtpm"
fixtures["az-tdx-vtpm"] = dict(
    source="deps/verifier/src/az_tdx_vtpm/mod.rs evaluate; tdx/claims.rs generate_parsed_claim; az_snp_vtpm/mod.rs extend_claim",
    claims=token("az-tdx-vtpm", pcr8(digest),
                 {"quote": td_quote(rtmrs=False), "td_attributes": td_attrs, "tcb_status": "UpToDate",
                  "tpm": {"pcr08": pcr8(digest), "pcr11": rv["tdx_pcr11"][0]}},
                 {"executables": 3, "hardware": 2, "configuration": 2}),
    deny={"wrong Init-Data": {EV + "/init_data": pcr8(other), AZT + "/tpm/pcr08": pcr8(other)},
          "debug on": {AZT + "/td_attributes/debug": True, AZT + "/quote/body/td_attributes": "0100001000000000"},
          "not affirming": {"/submods/cpu0/ear.status": "warning"}},
    required=["/submods/cpu0/ear.status", EV + "/init_data", AZT + "/td_attributes/debug",
              AZT + "/tpm/pcr11", AZT + "/quote/body/mr_td", AZT + "/quote/body/xfam"],
)

for tee, f in fixtures.items():
    with open(os.path.join(out, tee + ".json"), "w") as fh:
        json.dump(f, fh, indent=2)
        fh.write("\n")
print("digest", digest.hex(), "pcr8", pcr8(digest))
