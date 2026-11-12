package verifier_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
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
			// Paths and values from the tree are plaintext metadata (spec
			// §0.6); the error reaches stderr and the audit records.
			for _, leak := range []string{root, "InsecureAllowAll", "Postgres", "/opt/kbs", "storage/kbs", "as-signer",
				"tls.", "example.com", "8.8.8.8", "BEGIN"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("CheckSealedConfig error %q holds %q from the tree", err, leak)
				}
			}
		})
	}
}

// Workloads pin Trustee's certificate on top of their system CAs, so it may
// name only hosts that no public CA certifies. The check fails closed at the
// edges (ticket 18).
func TestSealedConfigChecksAllowOnlyClusterInternalTLSNames(t *testing.T) {
	tests := []struct {
		name string
		dns  []string
		ips  []string
		ok   bool
	}{
		{"Service name", []string{"trustee.default.svc"}, nil, true},
		{"default cluster domain", []string{"trustee.default.svc.cluster.local"}, nil, true},
		{"private-use TLD", []string{"trustee.internal"}, nil, true},
		{"private IPv4", nil, []string{"10.96.0.10"}, true},
		{"IPv6 ULA", nil, []string{"fd00::10"}, true},
		{"names and addresses", []string{"trustee.default.svc"}, []string{"192.168.1.5"}, true},
		{"cluster domain under a public name", []string{"trustee.default.svc.k8s.example.com"}, nil, false},
		{"private TLD", []string{"trustee.corp"}, nil, false},
		{"one public name among internal ones", []string{"trustee.default.svc", "trustee.example.com"}, nil, false},
		{"CGNAT ClusterIP", nil, []string{"100.64.0.10"}, false},
		{"public IPv6", nil, []string{"2001:4860:4860::8888"}, false},
		{"one public address among private ones", []string{"trustee.default.svc"}, []string{"10.0.0.1", "1.1.1.1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := trusteetest.Tree(t, verifier.TrusteeRoot)
			trusteetest.WriteTLS(t, dir, func(c *x509.Certificate) {
				c.DNSNames = tt.dns
				for _, ip := range tt.ips {
					c.IPAddresses = append(c.IPAddresses, net.ParseIP(ip))
				}
			})
			err := verifier.CheckSealedConfig(dir, verifier.TrusteeRoot)
			if tt.ok && err != nil {
				t.Fatalf("CheckSealedConfig = %v, want it to pass", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "outside the cluster")) {
				t.Fatalf("CheckSealedConfig = %v, want a host outside the cluster", err)
			}
		})
	}
}

func TestSealedConfigChecksNeedATree(t *testing.T) {
	if err := verifier.CheckSealedConfig(filepath.Join(t.TempDir(), "none"), verifier.TrusteeRoot); err == nil {
		t.Fatal("CheckSealedConfig passed a missing tree")
	}
	dir := trusteetest.Tree(t, verifier.TrusteeRoot)
	if err := os.WriteFile(filepath.Join(dir, verifier.ConfigFile), []byte("admin_secret = \"hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifier.CheckSealedConfig(dir, verifier.TrusteeRoot)
	if err == nil || !strings.Contains(err.Error(), "not valid TOML") {
		t.Fatalf("CheckSealedConfig = %v, want a parse error", err)
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "admin_secret") {
		t.Errorf("CheckSealedConfig error %q quotes the KBS config", err)
	}
}

// The embedded default is Trustee v0.22.0's kbs/sample_policies/default.rego.
func TestKBSDefaultResourcePolicyIsUpstreams(t *testing.T) {
	sum := sha256.Sum256([]byte(verifier.KBSDefaultResourcePolicy))
	if got, want := hex.EncodeToString(sum[:]), "499ca0280c1ed8f13aa335c3cddab4fbf6952eefa383a49cf77968a6b0fe6c60"; got != want {
		t.Errorf("sha256 = %s, want %s", got, want)
	}
}
