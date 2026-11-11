// Package policy builds a Security Operator's Operator Policy: what they will
// release their Share to, and the resource policy their Operator Verifier
// enforces before it does.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
)

// Files that Write puts in an Operator Policy directory.
const (
	PolicyFile         = "operator-policy.json"
	ResourcePolicyFile = "resource-policy.rego"
)

// TEE types with a claim profile, named as Trustee v0.22.0 names them in
// the EAR token's annotated evidence.
const (
	TEETPM       = "tpm"
	TEETDX       = "tdx"
	TEESNP       = "snp"
	TEEAzSNPVTPM = "az-snp-vtpm"
	TEEAzTDXVTPM = "az-tdx-vtpm"
)

// Reference values the tpm claim profile requires: the default AS policy
// marks TPM evidence affirming only when its AK and PCR11 are among these.
const (
	RefTrustedAKs = "trusted_aks"
	RefTPMPCR11   = "tpm_pcr11"
)

// profile is one TEE type's claim profile at Trustee v0.22.0.
// docs/claim-profiles.md cites the verifier source for every field.
type profile struct {
	// untested: no real-TEE run has passed on this TEE type's evidence.
	// Fixtures derived from the verifier source and swtpm runs do not count
	// (spec §11). Ticket 17's real-TEE run clears it for its TEE type.
	untested bool
	// initData is the init_data claim the verifier reports for an
	// Init-Data digest.
	initData func(digest [sha256.Size]byte) string
	// debugOff is the Rego condition that the TEE is not in debug mode.
	// TPM evidence has no debug state.
	debugOff string
	// refs are the reference values the default AS policy needs to mark
	// the evidence affirming, each with the claim checked against it.
	refs []ref
}

type ref struct{ name, claim string }

var profiles = map[string]profile{
	TEETPM: {
		// Only swtpm so far, whose keys live on the host.
		untested: true,
		initData: pcr8,
		refs:     []ref{{RefTrustedAKs, "evidence.tpm.ak_public"}, {RefTPMPCR11, "evidence.tpm.pcr11"}},
	},
	TEETDX: {
		untested: true,
		// MRCONFIGID is 48 bytes; the verifier pads the digest with zeros.
		initData: func(d [sha256.Size]byte) string { return hex.EncodeToString(append(d[:], make([]byte, 16)...)) },
		debugOff: "evidence.tdx.td_attributes.debug == false",
		refs: []ref{
			{"rtmr_1", "evidence.tdx.quote.body.rtmr_1"},
			{"rtmr_2", "evidence.tdx.quote.body.rtmr_2"},
			{"mr_td", "evidence.tdx.quote.body.mr_td"},
			{"xfam", "evidence.tdx.quote.body.xfam"},
		},
	},
	TEESNP: {
		untested: true,
		initData: func(d [sha256.Size]byte) string { return hex.EncodeToString(d[:]) },
		debugOff: "evidence.snp.policy_debug_allowed == false",
		refs: []ref{
			{"snp_launch_measurement", "evidence.snp.measurement"},
			{"snp_bootloader", "evidence.snp.reported_tcb_bootloader"},
			{"snp_microcode", "evidence.snp.reported_tcb_microcode"},
			{"snp_snp_svn", "evidence.snp.reported_tcb_snp"},
			{"snp_tee_svn", "evidence.snp.reported_tcb_tee"},
		},
	},
	TEEAzSNPVTPM: {
		untested: true,
		initData: pcr8,
		// This verifier reports the SNP policy bits as strings.
		debugOff: `evidence["az-snp-vtpm"].policy_debug_allowed == "false"`,
		refs: []ref{
			{"measurement", `evidence["az-snp-vtpm"].measurement`},
			{"snp_pcr11", `evidence["az-snp-vtpm"].tpm.pcr11`},
			{"tcb_bootloader", `evidence["az-snp-vtpm"].reported_tcb_bootloader`},
			{"tcb_microcode", `evidence["az-snp-vtpm"].reported_tcb_microcode`},
			{"tcb_snp", `evidence["az-snp-vtpm"].reported_tcb_snp`},
			{"tcb_tee", `evidence["az-snp-vtpm"].reported_tcb_tee`},
			{"smt_enabled", `evidence["az-snp-vtpm"].platform_smt_enabled`},
			{"tsme_enabled", `evidence["az-snp-vtpm"].platform_tsme_enabled`},
			{"abi_major", `evidence["az-snp-vtpm"].policy_abi_major`},
			{"abi_minor", `evidence["az-snp-vtpm"].policy_abi_minor`},
			{"single_socket", `evidence["az-snp-vtpm"].policy_single_socket`},
			{"smt_allowed", `evidence["az-snp-vtpm"].policy_smt_allowed`},
		},
	},
	TEEAzTDXVTPM: {
		untested: true,
		initData: pcr8,
		debugOff: `evidence["az-tdx-vtpm"].td_attributes.debug == false`,
		refs: []ref{
			{"tdx_pcr11", `evidence["az-tdx-vtpm"].tpm.pcr11`},
			{"mr_td", `evidence["az-tdx-vtpm"].quote.body.mr_td`},
			{"xfam", `evidence["az-tdx-vtpm"].quote.body.xfam`},
		},
	},
}

// pcr8 is what a TPM or vTPM's PCR8 holds once the guest extends it with
// the Init-Data digest: sha256(0^32 || digest).
func pcr8(d [sha256.Size]byte) string {
	v := sha256.Sum256(append(make([]byte, sha256.Size), d[:]...))
	return hex.EncodeToString(v[:])
}

// OperatorPolicy is a Security Operator's own record of what they release
// their Share to.
type OperatorPolicy struct {
	Version   int      `json:"version"`
	AcceptTEE []string `json:"accept_tee"`
	// InitDataSHA256 is the hex SHA-256 of the reviewed Init-Data TOML.
	InitDataSHA256 string `json:"init_data_sha256"`
	// ReferenceValues are loaded into the Operator Verifier's RVPS by name.
	// Values are JSON: SNP TCB versions are numbers.
	ReferenceValues map[string][]any `json:"reference_values"`
	BundleSHA256    string           `json:"bundle_sha256"`
	KeyID           string           `json:"key_id"`
	Index           int              `json:"index"`
	Commitment      string           `json:"commitment"`
	// UntestedProfiles marks a policy built with --allow-untested-profiles:
	// it may accept a TEE type that no real-TEE run has passed on, so it is
	// not a production Operator Policy.
	UntestedProfiles bool `json:"untested_profiles"`
	// ResourcePolicy is the Operator Verifier's KBS resource policy (Rego),
	// kept in its own file for review.
	ResourcePolicy string `json:"-"`
}

// Input is what `policy build` reads.
type Input struct {
	InitData        []byte // the reviewed Init-Data TOML, byte for byte
	ReferenceValues map[string][]any
	AcceptTEE       []string
	// AllowUntested lets the policy accept a TEE type whose claim profile
	// is untested. Such a policy is not a production Operator Policy.
	AllowUntested bool
	BundleSHA256  string
	Manifest      ceremony.Manifest
	Share         ceremony.ShareFile
}

// refName is what the Operator Verifier's storage accepts as a key.
var refName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Build checks in and returns the Operator Policy with its resource policy.
func Build(in Input) (OperatorPolicy, error) {
	digest, err := initDataDigest(in.InitData)
	if err != nil {
		return OperatorPolicy{}, err
	}
	if err := checkTEE(in.AcceptTEE, in.AllowUntested); err != nil {
		return OperatorPolicy{}, err
	}
	if err := checkReferenceValues(in.ReferenceValues, in.AcceptTEE); err != nil {
		return OperatorPolicy{}, err
	}
	if b, err := hex.DecodeString(in.BundleSHA256); err != nil || len(b) != sha256.Size || in.BundleSHA256 != strings.ToLower(in.BundleSHA256) {
		return OperatorPolicy{}, fmt.Errorf("bundle digest %q is not a SHA-256 in 64 lowercase hex characters", in.BundleSHA256)
	}
	commitment, err := in.Manifest.CommitmentFor(in.Share.Index)
	if err != nil {
		return OperatorPolicy{}, err
	}
	p := OperatorPolicy{
		Version:          ceremony.Version,
		AcceptTEE:        in.AcceptTEE,
		InitDataSHA256:   hex.EncodeToString(digest[:]),
		ReferenceValues:  in.ReferenceValues,
		BundleSHA256:     in.BundleSHA256,
		KeyID:            in.Manifest.KeyID,
		Index:            in.Share.Index,
		Commitment:       commitment,
		UntestedProfiles: in.AllowUntested,
	}
	if err := p.CheckShare(in.Share); err != nil {
		return OperatorPolicy{}, err
	}
	p.ResourcePolicy, err = resourcePolicy(digest, in.AcceptTEE, in.ReferenceValues)
	return p, err
}

// CheckShare refuses a Share file that this policy was not built for, or
// whose Share does not match its Share Commitment.
func (p OperatorPolicy) CheckShare(s ceremony.ShareFile) error {
	if s.KeyID != p.KeyID {
		return fmt.Errorf("the Share file has key_id %q, the Operator Policy %q", s.KeyID, p.KeyID)
	}
	if s.Index != p.Index {
		return fmt.Errorf("the Share file has index %d, the Operator Policy %d", s.Index, p.Index)
	}
	if ceremony.Commitment(s.Share) != p.Commitment {
		return fmt.Errorf("the Share with index %d does not match its Share Commitment", s.Index)
	}
	return nil
}

// initDataDigest returns the SHA-256 of the Init-Data TOML. The guest
// measures these exact bytes, so the digest is never taken from a pasted hash.
func initDataDigest(b []byte) ([sha256.Size]byte, error) {
	var doc struct {
		Algorithm string `toml:"algorithm"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("parse Init-Data: %w", err)
	}
	if doc.Algorithm != "sha256" {
		return [sha256.Size]byte{}, fmt.Errorf("Init-Data algorithm is %q; policy build needs sha256", doc.Algorithm)
	}
	return sha256.Sum256(b), nil
}

func checkTEE(tees []string, allowUntested bool) error {
	if len(tees) == 0 {
		return errors.New("accept at least one TEE type")
	}
	for _, t := range tees {
		p, ok := profiles[t]
		if !ok {
			return fmt.Errorf("no claim profile for TEE type %q", t)
		}
		if p.untested && !allowUntested {
			return fmt.Errorf("the %s claim profile is untested, so a production Operator Policy may not accept it; "+
				"allow untested profiles only for a non-production policy", t)
		}
	}
	return nil
}

func checkReferenceValues(rv map[string][]any, tees []string) error {
	for name := range rv {
		if !refName.MatchString(name) {
			return fmt.Errorf("reference value name %q: use letters, digits, '_', '.' and '-'", name)
		}
	}
	for _, t := range tees {
		for _, r := range profiles[t].refs {
			if len(rv[r.name]) == 0 {
				return fmt.Errorf("the %s claim profile needs reference value %q", t, r.name)
			}
		}
	}
	return nil
}

// resourcePolicy releases the Share to evidence that matches the claim
// profile of an accepted TEE type: the default AS policy marked it
// affirming, its init_data claim holds the Init-Data digest as that TEE
// reports it, debug is off, and each claim the profile's reference values
// cover is among them. The default AS policy checks those claims too; this
// policy checks them again. A missing claim leaves its condition
// undefined, so the rule does not hold.
func resourcePolicy(digest [sha256.Size]byte, tees []string, rv map[string][]any) (string, error) {
	used := map[string][]any{}
	var rules strings.Builder
	for _, t := range tees {
		p := profiles[t]
		fmt.Fprintf(&rules, `
# Claim profile %s.
allow if {
	cpu := input.submods.cpu0
	cpu["ear.status"] == "affirming"
	evidence := cpu["ear.veraison.annotated-evidence"]
	evidence.init_data == %q
`, t, p.initData(digest))
		if p.debugOff != "" {
			fmt.Fprintf(&rules, "\t%s\n", p.debugOff)
		}
		for _, r := range p.refs {
			fmt.Fprintf(&rules, "\t%s in reference_values[%q]\n", r.claim, r.name)
			used[r.name] = rv[r.name]
		}
		rules.WriteString("}\n")
	}
	// One value per line: KBS's Rego engine refuses long lines.
	vals, err := json.MarshalIndent(used, "", "\t")
	if err != nil {
		return "", fmt.Errorf("encode reference values: %w", err)
	}
	// JSON values are Rego literals.
	rego := fmt.Sprintf(`# Operator Verifier resource policy, from trustee-bootstrap policy build.
# Claim profiles: %s (docs/claim-profiles.md).
package policy

import rego.v1

default allow := false

reference_values := %s
`, strings.Join(tees, ", "), vals) + rules.String()
	for _, line := range strings.Split(rego, "\n") {
		// The lexer counts a tab as 4 columns.
		if w := len(line) + 3*strings.Count(line, "\t"); w > maxRegoColumns {
			return "", fmt.Errorf("resource policy line %.40q... is %d columns wide; KBS's Rego engine refuses lines over %d",
				line, w, maxRegoColumns)
		}
	}
	return rego, nil
}

// maxRegoColumns is the widest line regorus 0.11.0, KBS v0.22.0's Rego
// engine, parses: its lexer refuses a column past 1024, counting from 1.
const maxRegoColumns = 1023

// Write stores p in dir, which it creates 0700.
func Write(dir string, p OperatorPolicy) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Operator Policy: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PolicyFile), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write Operator Policy: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ResourcePolicyFile), []byte(p.ResourcePolicy), 0o600); err != nil {
		return fmt.Errorf("write resource policy: %w", err)
	}
	return nil
}

// Load reads the Operator Policy that Write stored in dir.
func Load(dir string) (OperatorPolicy, error) {
	var p OperatorPolicy
	b, err := os.ReadFile(filepath.Join(dir, PolicyFile))
	if err != nil {
		return p, fmt.Errorf("read Operator Policy: %w", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("parse Operator Policy: %w", err)
	}
	rego, err := os.ReadFile(filepath.Join(dir, ResourcePolicyFile))
	if err != nil {
		return p, fmt.Errorf("read resource policy: %w", err)
	}
	p.ResourcePolicy = string(rego)
	return p, nil
}
