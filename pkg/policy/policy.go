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

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
)

// Files that Write puts in an Operator Policy directory.
const (
	PolicyFile         = "operator-policy.json"
	ResourcePolicyFile = "resource-policy.rego"
)

// TEETPM is the TPM attester's TEE type. It is the only claim profile so far.
const TEETPM = "tpm"

// Reference values the tpm claim profile requires: the default AS policy
// marks TPM evidence affirming only when its AK and PCR11 are among these.
const (
	RefTrustedAKs = "trusted_aks"
	RefTPMPCR11   = "tpm_pcr11"
)

// OperatorPolicy is a Security Operator's own record of what they release
// their Share to.
type OperatorPolicy struct {
	Version   int      `json:"version"`
	AcceptTEE []string `json:"accept_tee"`
	// InitDataSHA256 is the hex SHA-256 of the reviewed Init-Data TOML.
	InitDataSHA256 string `json:"init_data_sha256"`
	// ReferenceValues are loaded into the Operator Verifier's RVPS by name.
	ReferenceValues map[string][]string `json:"reference_values"`
	BundleSHA256    string              `json:"bundle_sha256"`
	KeyID           string              `json:"key_id"`
	Index           int                 `json:"index"`
	Commitment      string              `json:"commitment"`
	// ResourcePolicy is the Operator Verifier's KBS resource policy (Rego),
	// kept in its own file for review.
	ResourcePolicy string `json:"-"`
}

// Input is what `policy build` reads.
type Input struct {
	InitData        []byte // the reviewed Init-Data TOML, byte for byte
	ReferenceValues map[string][]string
	AcceptTEE       []string
	BundleSHA256    string
	Manifest        ceremony.Manifest
	Share           ceremony.ShareFile
}

// refName is what the Operator Verifier's storage accepts as a key.
var refName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Build checks in and returns the Operator Policy with its resource policy.
func Build(in Input) (OperatorPolicy, error) {
	digest, err := initDataDigest(in.InitData)
	if err != nil {
		return OperatorPolicy{}, err
	}
	if err := checkTEE(in.AcceptTEE); err != nil {
		return OperatorPolicy{}, err
	}
	if err := checkReferenceValues(in.ReferenceValues); err != nil {
		return OperatorPolicy{}, err
	}
	if b, err := hex.DecodeString(in.BundleSHA256); err != nil || len(b) != sha256.Size {
		return OperatorPolicy{}, fmt.Errorf("bundle digest %q is not a hex SHA-256", in.BundleSHA256)
	}
	commitment, err := in.Manifest.CommitmentFor(in.Share.Index)
	if err != nil {
		return OperatorPolicy{}, err
	}
	p := OperatorPolicy{
		Version:         ceremony.Version,
		AcceptTEE:       in.AcceptTEE,
		InitDataSHA256:  hex.EncodeToString(digest[:]),
		ReferenceValues: in.ReferenceValues,
		BundleSHA256:    in.BundleSHA256,
		KeyID:           in.Manifest.KeyID,
		Index:           in.Share.Index,
		Commitment:      commitment,
	}
	if err := p.CheckShare(in.Share); err != nil {
		return OperatorPolicy{}, err
	}
	p.ResourcePolicy, err = tpmResourcePolicy(digest, in.ReferenceValues)
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
		return [sha256.Size]byte{}, fmt.Errorf("Init-Data algorithm is %q; the tpm claim profile needs sha256", doc.Algorithm)
	}
	return sha256.Sum256(b), nil
}

func checkTEE(tees []string) error {
	if len(tees) == 0 {
		return errors.New("accept at least one TEE type")
	}
	for _, t := range tees {
		if t != TEETPM {
			return fmt.Errorf("no claim profile for TEE type %q", t)
		}
	}
	return nil
}

func checkReferenceValues(rv map[string][]string) error {
	for name := range rv {
		if !refName.MatchString(name) {
			return fmt.Errorf("reference value name %q: use letters, digits, '_', '.' and '-'", name)
		}
	}
	for _, name := range []string{RefTrustedAKs, RefTPMPCR11} {
		if len(rv[name]) == 0 {
			return fmt.Errorf("the tpm claim profile needs reference value %q", name)
		}
	}
	return nil
}

// tpmResourcePolicy is the tpm claim profile. The TPM attester extends PCR8
// with the Init-Data digest, and the verifier reports PCR8 as the init_data
// claim, so it must equal sha256(0^32 || digest). The AK and PCR11 are
// checked twice: by the default AS policy (affirming) and here. TPM evidence
// has no debug state to check.
func tpmResourcePolicy(digest [sha256.Size]byte, rv map[string][]string) (string, error) {
	pcr8 := sha256.Sum256(append(make([]byte, sha256.Size), digest[:]...))
	vals, err := json.Marshal([]any{hex.EncodeToString(pcr8[:]), rv[RefTrustedAKs], rv[RefTPMPCR11]})
	if err != nil {
		return "", fmt.Errorf("encode reference values: %w", err)
	}
	// JSON values are Rego literals.
	return fmt.Sprintf(`# Operator Verifier resource policy, from trustee-bootstrap policy build.
# Claim profile: tpm.
package policy

import rego.v1

default allow := false

expected := %s

allow if {
	cpu := input.submods.cpu0
	cpu["ear.status"] == "affirming"
	evidence := cpu["ear.veraison.annotated-evidence"]
	evidence.init_data == expected[0]
	evidence.tpm.ak_public in expected[1]
	evidence.tpm.pcr11 in expected[2]
}
`, vals), nil
}

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
