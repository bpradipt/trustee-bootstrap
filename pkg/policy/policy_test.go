package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
)

const initData = `version = "0.1.0"
algorithm = "sha256"
[data]
"aa.toml" = '''
[token_configs.kbs]
url = "http://127.0.0.1:8081"
'''
`

const (
	ak    = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	pcr11 = "0000000000000000000000000000000000000000000000000000000000000000"
)

func input(t *testing.T) policy.Input {
	t.Helper()
	m, files, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	return policy.Input{
		InitData:        []byte(initData),
		ReferenceValues: map[string][]any{policy.RefTrustedAKs: {ak}, policy.RefTPMPCR11: {pcr11}},
		AcceptTEE:       []string{policy.TEETPM},
		AllowUntested:   true,
		BundleSHA256:    strings.Repeat("ab", sha256.Size),
		Manifest:        m,
		Share:           files[1],
	}
}

func TestBuildTPM(t *testing.T) {
	in := input(t)
	in.ReferenceValues["unused"] = []any{"x"}
	p, err := policy.Build(in)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(initData))
	if p.InitDataSHA256 != hex.EncodeToString(digest[:]) {
		t.Errorf("init_data_sha256 = %s, want the SHA-256 of the Init-Data bytes", p.InitDataSHA256)
	}
	want := policy.OperatorPolicy{
		Version: 1, AcceptTEE: in.AcceptTEE, InitDataSHA256: p.InitDataSHA256, ReferenceValues: in.ReferenceValues,
		BundleSHA256: in.BundleSHA256, KeyID: in.Manifest.KeyID, Index: 2, Commitment: in.Manifest.Shares[1].Commitment,
		UntestedProfiles: true, ResourcePolicy: p.ResourcePolicy,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("Build = %+v\nwant %+v", p, want)
	}
	pcr8 := sha256.Sum256(append(make([]byte, 32), digest[:]...))
	for _, s := range []string{
		"reference_values := {\n\t\"tpm_pcr11\": [\n\t\t\"" + pcr11 + "\"\n\t],\n\t\"trusted_aks\": [\n\t\t\"" + ak + "\"\n\t]\n}\n",
		"default allow := false",
		"# Claim profile tpm.\nallow if {\n",
		`cpu["ear.status"] == "affirming"`,
		`evidence.init_data == "` + hex.EncodeToString(pcr8[:]) + `"` + "\n\tevidence.tpm.ak_public",
		`evidence.tpm.ak_public in reference_values["trusted_aks"]`,
		`evidence.tpm.pcr11 in reference_values["tpm_pcr11"]`,
	} {
		if !strings.Contains(p.ResourcePolicy, s) {
			t.Errorf("resource policy lacks %s:\n%s", s, p.ResourcePolicy)
		}
	}
	if strings.Contains(p.ResourcePolicy, "unused") {
		t.Errorf("resource policy holds a reference value no profile checks:\n%s", p.ResourcePolicy)
	}
}

// allReferenceValues holds every reference value any claim profile needs.
func allReferenceValues() map[string][]any {
	rv := map[string][]any{policy.RefTrustedAKs: {ak}, policy.RefTPMPCR11: {pcr11}}
	for _, name := range []string{
		"rtmr_1", "rtmr_2", "mr_td", "xfam", "snp_launch_measurement", "measurement", "snp_pcr11", "tdx_pcr11",
		"tcb_bootloader", "tcb_microcode", "tcb_snp", "tcb_tee", "smt_enabled", "tsme_enabled",
		"abi_major", "abi_minor", "single_socket", "smt_allowed",
	} {
		rv[name] = []any{"v-" + name}
	}
	for _, name := range []string{"snp_bootloader", "snp_microcode", "snp_snp_svn", "snp_tee_svn"} {
		rv[name] = []any{float64(7)}
	}
	return rv
}

func TestBuildProfiles(t *testing.T) {
	digest := sha256.Sum256([]byte(initData))
	pcr8 := sha256.Sum256(append(make([]byte, 32), digest[:]...))
	tests := []struct {
		tee      string
		initData string
		lines    []string
	}{
		{policy.TEETDX, hex.EncodeToString(digest[:]) + strings.Repeat("0", 32), []string{
			"evidence.tdx.td_attributes.debug == false",
			`evidence.tdx.quote.body.rtmr_1 in reference_values["rtmr_1"]`,
			`evidence.tdx.quote.body.rtmr_2 in reference_values["rtmr_2"]`,
			`evidence.tdx.quote.body.mr_td in reference_values["mr_td"]`,
			`evidence.tdx.quote.body.xfam in reference_values["xfam"]`,
		}},
		{policy.TEESNP, hex.EncodeToString(digest[:]), []string{
			"evidence.snp.policy_debug_allowed == false",
			`evidence.snp.measurement in reference_values["snp_launch_measurement"]`,
			`evidence.snp.reported_tcb_bootloader in reference_values["snp_bootloader"]`,
			`evidence.snp.reported_tcb_microcode in reference_values["snp_microcode"]`,
			`evidence.snp.reported_tcb_snp in reference_values["snp_snp_svn"]`,
			`evidence.snp.reported_tcb_tee in reference_values["snp_tee_svn"]`,
			"\"snp_bootloader\": [\n\t\t7\n\t]",
		}},
		{policy.TEEAzSNPVTPM, hex.EncodeToString(pcr8[:]), []string{
			`evidence["az-snp-vtpm"].policy_debug_allowed == "false"`,
			`evidence["az-snp-vtpm"].measurement in reference_values["measurement"]`,
			`evidence["az-snp-vtpm"].tpm.pcr11 in reference_values["snp_pcr11"]`,
			`evidence["az-snp-vtpm"].policy_smt_allowed in reference_values["smt_allowed"]`,
		}},
		{policy.TEEAzTDXVTPM, hex.EncodeToString(pcr8[:]), []string{
			`evidence["az-tdx-vtpm"].td_attributes.debug == false`,
			`evidence["az-tdx-vtpm"].tpm.pcr11 in reference_values["tdx_pcr11"]`,
			`evidence["az-tdx-vtpm"].quote.body.mr_td in reference_values["mr_td"]`,
			`evidence["az-tdx-vtpm"].quote.body.xfam in reference_values["xfam"]`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.tee, func(t *testing.T) {
			in := input(t)
			in.AcceptTEE = []string{tt.tee}
			in.ReferenceValues = allReferenceValues()
			in.AllowUntested = true
			p, err := policy.Build(in)
			if err != nil {
				t.Fatal(err)
			}
			head := "# Claim profile " + tt.tee + ".\nallow if {\n"
			for _, s := range append(tt.lines, head, `evidence.init_data == "`+tt.initData+`"`+"\n\t"+tt.lines[0]) {
				if !strings.Contains(p.ResourcePolicy, s) {
					t.Errorf("resource policy lacks %s:\n%s", s, p.ResourcePolicy)
				}
			}
			if strings.Contains(p.ResourcePolicy, "trusted_aks") {
				t.Errorf("resource policy checks the tpm profile too:\n%s", p.ResourcePolicy)
			}
		})
	}
}

func TestBuildManyProfiles(t *testing.T) {
	in := input(t)
	in.AcceptTEE = []string{policy.TEETPM, policy.TEESNP}
	in.ReferenceValues = allReferenceValues()
	in.AllowUntested = true
	p, err := policy.Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(p.ResourcePolicy, "allow if {"); n != 2 {
		t.Errorf("resource policy has %d allow rules, want 2:\n%s", n, p.ResourcePolicy)
	}
	if !strings.Contains(p.ResourcePolicy, "# Claim profiles: tpm, snp") {
		t.Errorf("resource policy does not name its profiles:\n%s", p.ResourcePolicy)
	}
}

// KBS's Rego engine (regorus 0.11.0) refuses lines past column 1024, so
// Build refuses a reference value that would make one.
func TestBuildLongLine(t *testing.T) {
	in := input(t)
	// Two tabs (4 columns each), the quotes and the value.
	in.ReferenceValues[policy.RefTrustedAKs] = []any{strings.Repeat("A", 1013)}
	if _, err := policy.Build(in); err != nil {
		t.Errorf("Build with a 1023-column line: %v", err)
	}
	in.ReferenceValues[policy.RefTrustedAKs] = []any{strings.Repeat("A", 1014)}
	if _, err := policy.Build(in); err == nil || !strings.Contains(err.Error(), "is 1024 columns wide") {
		t.Errorf("Build with a 1024-column line = %v, want a line width error", err)
	}
}

func TestBuildRefusesUntested(t *testing.T) {
	for _, tee := range []string{policy.TEETPM, policy.TEETDX, policy.TEESNP, policy.TEEAzSNPVTPM, policy.TEEAzTDXVTPM} {
		t.Run(tee, func(t *testing.T) {
			in := input(t)
			in.AcceptTEE = []string{tee}
			in.ReferenceValues = allReferenceValues()
			in.AllowUntested = false
			want := "the " + tee + " claim profile is untested"
			if _, err := policy.Build(in); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Build error = %v, want %q", err, want)
			}
		})
	}
}

func TestBuildRefuses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*policy.Input)
		want   string
	}{
		{"bad TOML", func(in *policy.Input) { in.InitData = []byte("algorithm = ") }, "parse Init-Data"},
		{"sha384 Init-Data", func(in *policy.Input) {
			in.InitData = []byte(strings.Replace(initData, "sha256", "sha384", 1))
		}, "needs sha256"},
		{"no TEE", func(in *policy.Input) { in.AcceptTEE = nil }, "at least one TEE"},
		{"no profile", func(in *policy.Input) { in.AcceptTEE = []string{"tpm", "sev"} }, `TEE type "sev"`},
		{"no trusted AKs", func(in *policy.Input) { delete(in.ReferenceValues, policy.RefTrustedAKs) }, "trusted_aks"},
		{"no PCR11", func(in *policy.Input) { in.ReferenceValues[policy.RefTPMPCR11] = nil }, "tpm_pcr11"},
		{"tdx without mr_td", func(in *policy.Input) {
			in.AcceptTEE, in.AllowUntested, in.ReferenceValues = []string{policy.TEETDX}, true, allReferenceValues()
			delete(in.ReferenceValues, "mr_td")
		}, `the tdx claim profile needs reference value "mr_td"`},
		{"path in name", func(in *policy.Input) { in.ReferenceValues["../x"] = []any{"y"} }, `"../x"`},
		{"short digest", func(in *policy.Input) { in.BundleSHA256 = "abcd" }, "64 lowercase hex characters"},
		{"non-hex digest", func(in *policy.Input) { in.BundleSHA256 = strings.Repeat("zz", 32) }, "64 lowercase hex characters"},
		{"uppercase digest", func(in *policy.Input) { in.BundleSHA256 = strings.Repeat("AB", 32) }, "64 lowercase hex characters"},
		{"unknown index", func(in *policy.Input) { in.Share.Index = 4 }, "no share index 4"},
		{"other ceremony", func(in *policy.Input) { in.Share.KeyID = "other" }, `key_id "other"`},
		{"forged Share", func(in *policy.Input) { in.Share.Share = []byte("forged") }, "Share Commitment"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := input(t)
			tt.change(&in)
			if _, err := policy.Build(in); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Build error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckShare(t *testing.T) {
	in := input(t)
	p, err := policy.Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckShare(in.Share); err != nil {
		t.Errorf("CheckShare(own Share) = %v", err)
	}
	other := in.Share
	other.Index = 3
	if err := p.CheckShare(other); err == nil || !strings.Contains(err.Error(), "index 3") {
		t.Errorf("CheckShare(index 3) = %v, want an index error", err)
	}
}

func TestWriteLoad(t *testing.T) {
	p, err := policy.Build(input(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "policy")
	if err := policy.Write(dir, p); err != nil {
		t.Fatal(err)
	}
	got, err := policy.Load(dir)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Errorf("Load = %+v, %v; want %+v", got, err, p)
	}
	if err := policy.Write(dir, p); err != nil {
		t.Errorf("rewrite: %v", err)
	}
	if _, err := policy.Load(t.TempDir()); err == nil {
		t.Error("Load of an empty directory succeeded")
	}
}

// A policy built with --allow-untested-profiles says so in its file, for a
// reviewer, and keeps saying so through Load.
func TestUntestedProfilesAreMarked(t *testing.T) {
	p, err := policy.Build(input(t))
	if err != nil {
		t.Fatal(err)
	}
	if !p.UntestedProfiles {
		t.Error("UntestedProfiles = false for a policy built with AllowUntested")
	}
	dir := t.TempDir()
	if err := policy.Write(dir, p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, policy.PolicyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"untested_profiles": true`) {
		t.Errorf("%s has no untested_profiles marker:\n%s", policy.PolicyFile, b)
	}
}
