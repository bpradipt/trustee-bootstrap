package verifier_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// The example Trustee config, sealed with its signer and a resource policy,
// passes every sealed-config check.
func TestExampleTrusteeConfigPassesSealedConfigChecks(t *testing.T) {
	dir := trusteetest.Tree(t, verifier.TrusteeRoot)
	example, err := os.ReadFile("../../deploy/examples/trustee-config/kbs.toml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, verifier.ConfigFile), example, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.CheckSealedConfig(dir, verifier.TrusteeRoot); err != nil {
		t.Fatalf("CheckSealedConfig = %v", err)
	}
}

// AT-27: each violation fails its own check, and only that one.
func TestSealedConfigChecksRefuseEachViolation(t *testing.T) {
	for _, v := range trusteetest.Violations {
		t.Run(v.Name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "trustee")
			dir := trusteetest.Tree(t, root)
			if err := verifier.CheckSealedConfig(dir, root); err != nil {
				t.Fatalf("before the violation: %v", err)
			}
			v.Apply(t, dir)
			err := verifier.CheckSealedConfig(dir, root)
			if err == nil || !strings.Contains(err.Error(), v.Want) {
				t.Fatalf("CheckSealedConfig = %v, want it to name %s", err, v.Want)
			}
			if n := len(strings.Split(err.Error(), "\n")); n != 1 {
				t.Errorf("CheckSealedConfig reported %d problems, want 1: %v", n, err)
			}
		})
	}
}

func TestSealedConfigChecksNeedATree(t *testing.T) {
	if err := verifier.CheckSealedConfig(filepath.Join(t.TempDir(), "none"), verifier.TrusteeRoot); err == nil {
		t.Fatal("CheckSealedConfig passed a missing tree")
	}
	dir := trusteetest.Tree(t, verifier.TrusteeRoot)
	if err := os.WriteFile(filepath.Join(dir, verifier.ConfigFile), []byte("insecure_http = "), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifier.CheckSealedConfig(dir, verifier.TrusteeRoot); err == nil || !strings.Contains(err.Error(), "parse KBS config") {
		t.Fatalf("CheckSealedConfig = %v, want a parse error", err)
	}
}

// The embedded default is Trustee v0.22.0's kbs/sample_policies/default.rego.
func TestKBSDefaultResourcePolicyIsUpstreams(t *testing.T) {
	sum := sha256.Sum256([]byte(verifier.KBSDefaultResourcePolicy))
	if got, want := hex.EncodeToString(sum[:]), "499ca0280c1ed8f13aa335c3cddab4fbf6952eefa383a49cf77968a6b0fe6c60"; got != want {
		t.Errorf("sha256 = %s, want %s", got, want)
	}
}
