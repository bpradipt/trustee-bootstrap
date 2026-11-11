package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
)

// An untested claim profile needs --allow-untested-profiles, and its
// numeric reference values reach the Operator Policy as numbers.
func TestPolicyBuildUntestedProfile(t *testing.T) {
	dir := t.TempDir()
	mustRun(t, "ceremony", "split", "--threshold", "2", "--holders", "alice,bob", "--out-dir", dir)
	initData := filepath.Join(dir, "init.toml")
	rv := filepath.Join(dir, "rv.json")
	if err := os.WriteFile(initData, []byte("version = \"0.1.0\"\nalgorithm = \"sha256\"\n[data]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rv, []byte(`{"snp_launch_measurement":["ab"],"snp_bootloader":[3],"snp_microcode":[4],`+
		`"snp_snp_svn":[5],"snp_tee_svn":[6]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "policy")
	args := []string{"policy", "build", "--init-data", initData, "--reference-values", rv, "--accept-tee", "snp",
		"--bundle-sha256", strings.Repeat("ab", 32), "--manifest", filepath.Join(dir, cli.ManifestFile),
		"--share-file", filepath.Join(dir, "alice.share"), "--out-dir", out}
	if _, err := run(t, args...); err == nil || !strings.Contains(err.Error(), "untested") {
		t.Fatalf("policy build --accept-tee snp = %v, want an untested-profile error", err)
	}
	mustRun(t, append(args, "--allow-untested-profiles")...)
	p, err := policy.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.ReferenceValues["snp_bootloader"]; len(got) != 1 || got[0] != float64(3) {
		t.Errorf("snp_bootloader = %#v, want the number 3", got)
	}
}
