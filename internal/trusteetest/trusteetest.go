// Package trusteetest writes Trustee config trees for tests: one that passes
// the sealed-config checks, and the violations that each fail one of them.
package trusteetest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// ResourcePolicy is the resource policy Tree seals.
const ResourcePolicy = "package policy\n\ndefault allow := false\n"

// Tree writes a Trustee config tree into a new directory and returns it.
// Seen by Trustee at root, it passes the sealed-config checks: the default
// secure Trustee config, the AS signer's key and certificate, and a resource
// policy at the storage backend's exact key.
func Tree(t testing.TB, root string) string {
	t.Helper()
	dir := t.TempDir()
	writeConfig(t, dir, verifier.DefaultTrusteeConfig(root))
	err := os.MkdirAll(filepath.Join(dir, filepath.Dir(verifier.ResourcePolicyPath)), 0o700)
	for name, body := range map[string]string{
		verifier.SignerKeyFile:      "test AS signer key\n",
		verifier.SignerCertFile:     "test AS signer certificate\n",
		verifier.ResourcePolicyPath: ResourcePolicy,
	} {
		err = errors.Join(err, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// Violation breaks one sealed-config check in a Tree.
type Violation struct {
	Name  string
	Want  string // text the check's error carries
	Apply func(t testing.TB, dir string)
}

// Violations holds one Violation per sealed-config check (AT-27).
var Violations = []Violation{
	{"insecure_header_jwk", "insecure_header_jwk", editConfig(func(c *verifier.Config) { c.AttestationToken.InsecureHeaderJWK = true })},
	{"insecure_http", "insecure_http", editConfig(func(c *verifier.Config) { c.HTTPServer.InsecureHTTP = true })},
	{"InsecureAllowAll", "authorization_mode", editConfig(func(c *verifier.Config) { c.Admin.AuthorizationMode = "InsecureAllowAll" })},
	{"missing KBS config", "KBS config", remove(verifier.ConfigFile)},
	{"missing signer key", "AS signer key", remove(verifier.SignerKeyFile)},
	{"missing signer certificate", "AS signer certificate", remove(verifier.SignerCertFile)},
	{"unlisted signer certificate", "trusted_certs_paths", editConfig(func(c *verifier.Config) { c.AttestationToken.TrustedCertsPaths = nil })},
	{"missing resource policy", "resource policy", remove(verifier.ResourcePolicyPath)},
	{"misplaced resource policy", "resource policy", func(t testing.TB, dir string) {
		t.Helper()
		if err := os.Rename(filepath.Join(dir, verifier.ResourcePolicyPath), filepath.Join(dir, "resource-policy.rego")); err != nil {
			t.Fatal(err)
		}
	}},
	{"storage outside the tree", "outside the sealed tree", editConfig(func(c *verifier.Config) { c.StorageBackend.Backends.LocalFS.DirPath = "/opt/kbs" })},
	{"storage not LocalFs", "storage_type", editConfig(func(c *verifier.Config) { c.StorageBackend.StorageType = "Memory" })},
	{"empty resource policy", "empty", writePolicy("# allow nothing\n\n")},
	{"default resource policy", "built-in default", writePolicy(verifier.KBSDefaultResourcePolicy)},
	{"default resource policy, reformatted", "built-in default", writePolicy(strings.ReplaceAll(
		verifier.KBSDefaultResourcePolicy[strings.Index(verifier.KBSDefaultResourcePolicy, "package"):], "\t", "    "))},
}

func writeConfig(t testing.TB, dir string, c verifier.Config) {
	t.Helper()
	var b bytes.Buffer
	err := toml.NewEncoder(&b).Encode(c)
	if err := errors.Join(err, os.WriteFile(filepath.Join(dir, verifier.ConfigFile), b.Bytes(), 0o600)); err != nil {
		t.Fatal(err)
	}
}

func editConfig(edit func(*verifier.Config)) func(testing.TB, string) {
	return func(t testing.TB, dir string) {
		t.Helper()
		var c verifier.Config
		if _, err := toml.DecodeFile(filepath.Join(dir, verifier.ConfigFile), &c); err != nil {
			t.Fatal(err)
		}
		edit(&c)
		writeConfig(t, dir, c)
	}
}

func remove(name string) func(testing.TB, string) {
	return func(t testing.TB, dir string) {
		t.Helper()
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func writePolicy(policy string) func(testing.TB, string) {
	return func(t testing.TB, dir string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, verifier.ResourcePolicyPath), []byte(policy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
