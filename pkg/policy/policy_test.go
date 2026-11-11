package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
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
		ReferenceValues: map[string][]string{policy.RefTrustedAKs: {ak}, policy.RefTPMPCR11: {pcr11}},
		AcceptTEE:       []string{policy.TEETPM},
		BundleSHA256:    strings.Repeat("ab", sha256.Size),
		Manifest:        m,
		Share:           files[1],
	}
}

func TestBuildTPM(t *testing.T) {
	in := input(t)
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
		ResourcePolicy: p.ResourcePolicy,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("Build = %+v\nwant %+v", p, want)
	}
	pcr8 := sha256.Sum256(append(make([]byte, 32), digest[:]...))
	for _, s := range []string{
		`expected := ["` + hex.EncodeToString(pcr8[:]) + `",["` + ak + `"],["` + pcr11 + `"]]`,
		`cpu["ear.status"] == "affirming"`,
		"evidence.init_data == expected[0]",
		"evidence.tpm.ak_public in expected[1]",
		"evidence.tpm.pcr11 in expected[2]",
		"default allow := false",
	} {
		if !strings.Contains(p.ResourcePolicy, s) {
			t.Errorf("resource policy lacks %s:\n%s", s, p.ResourcePolicy)
		}
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
		{"no profile", func(in *policy.Input) { in.AcceptTEE = []string{"tpm", "snp"} }, `TEE type "snp"`},
		{"no trusted AKs", func(in *policy.Input) { delete(in.ReferenceValues, policy.RefTrustedAKs) }, "trusted_aks"},
		{"no PCR11", func(in *policy.Input) { in.ReferenceValues[policy.RefTPMPCR11] = nil }, "tpm_pcr11"},
		{"path in name", func(in *policy.Input) { in.ReferenceValues["../x"] = []string{"y"} }, `"../x"`},
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
