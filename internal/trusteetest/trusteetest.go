// Package trusteetest writes Trustee config trees for tests: one that passes
// the sealed-config checks, and the violations that each fail one of them.
package trusteetest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// ResourcePolicy is the resource policy Tree seals.
const ResourcePolicy = "package policy\n\ndefault allow := false\n"

// TrusteeHost is the cluster-internal name that Tree's TLS certificate
// carries, like the one the seal runbook makes.
const TrusteeHost = "trustee.default.svc.cluster.local"

// Tree writes a Trustee config tree into a new directory and returns it.
// Seen by Trustee at root, it passes the sealed-config checks: the default
// secure Trustee config, Trustee's TLS key and certificate, the AS signer's
// key and certificate, and a resource policy at the storage backend's exact
// key.
func Tree(t testing.TB, root string) string {
	t.Helper()
	dir := t.TempDir()
	writeConfig(t, dir, verifier.DefaultTrusteeConfig(root))
	WriteTLS(t, dir, nil)
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
	{"sessions not in memory", "session_storage_type", editConfig(func(c *verifier.Config) { c.SessionStorageType = "Postgres" })},
	{"empty resource policy", "empty", writePolicy("# allow nothing\n\n")},
	{"default resource policy", "built-in default", writePolicy(verifier.KBSDefaultResourcePolicy)},
	{"default resource policy, reformatted", "built-in default", writePolicy(strings.ReplaceAll(
		verifier.KBSDefaultResourcePolicy[strings.Index(verifier.KBSDefaultResourcePolicy, "package"):], "\t", "    "))},
	{"missing TLS key", "[http_server] private_key", remove(verifier.TLSKeyFile)},
	{"missing TLS certificate", "[http_server] certificate", remove(verifier.TLSCertFile)},
	{"TLS key from another pair", "not a matching", otherTLSKey},
	{"CA TLS certificate", "CA certificate", tlsCert(func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage |= x509.KeyUsageCertSign
	})},
	{"TLS certificate without names", "names no DNS name or IP address", tlsCert(func(c *x509.Certificate) { c.DNSNames = nil })},
	{"public DNS name", "outside the cluster", tlsCert(func(c *x509.Certificate) { c.DNSNames = []string{"trustee.example.com"} })},
	{"public IP address", "outside the cluster", tlsCert(func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = []net.IP{net.ParseIP("8.8.8.8")}
	})},
}

// WriteTLS writes Trustee's HTTPS key and a self-signed leaf certificate for
// it into a Tree, after edit changes the certificate template. Unedited, the
// leaf names TrusteeHost. It sets no validity period: the sealed-config
// checks leave expiry to Trustee and the workloads' TLS stack.
func WriteTLS(t testing.TB, dir string, edit func(*x509.Certificate)) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: TrusteeHost},
		DNSNames:              []string{TrusteeHost},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if edit != nil {
		edit(cert)
	}
	certDER, certErr := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	keyDER, keyErr := x509.MarshalPKCS8PrivateKey(key)
	if err := errors.Join(certErr, keyErr,
		os.WriteFile(filepath.Join(dir, verifier.TLSKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600),
		os.WriteFile(filepath.Join(dir, verifier.TLSCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600),
	); err != nil {
		t.Fatal(err)
	}
}

func tlsCert(edit func(*x509.Certificate)) func(testing.TB, string) {
	return func(t testing.TB, dir string) {
		t.Helper()
		WriteTLS(t, dir, edit)
	}
}

// otherTLSKey puts the key of another, valid pair next to the tree's
// certificate.
func otherTLSKey(t testing.TB, dir string) {
	t.Helper()
	other := t.TempDir()
	WriteTLS(t, other, nil)
	key, err := os.ReadFile(filepath.Join(other, verifier.TLSKeyFile))
	if err := errors.Join(err, os.WriteFile(filepath.Join(dir, verifier.TLSKeyFile), key, 0o600)); err != nil {
		t.Fatal(err)
	}
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
