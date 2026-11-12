package verifier

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// AdminAuthenticated is the only admin authorization_mode the Operator
// Verifier accepts: every admin call needs a token signed by the admin key.
const AdminAuthenticated = "AuthenticatedAuthorization"

// Files in an Operator Verifier's run directory, relative to it.
const (
	ConfigFile         = "kbs.toml"
	AdminPublicKeyFile = "admin.pub"     // the ephemeral admin key; its private half is never kept
	SignerKeyFile      = "as-signer.key" // the AS token signer, generated per run
	SignerCertFile     = "as-signer.crt" // its self-signed certificate, the only one KBS trusts
	StorageDir         = "storage"       // the KBS LocalFs storage backend
	// ResourcePolicyPath holds the KBS resource policy: storage namespace
	// "kbs", key "resource-policy.rego" (Trustee v0.22.0 KBS_POLICY_ID).
	// KBS installs its built-in default policy whenever this file is absent.
	ResourcePolicyPath = "storage/kbs/resource-policy.rego"
)

// Files that only a Trustee config tree has, relative to its root.
const (
	TLSKeyFile  = "tls.key" // Trustee's HTTPS key, sealed in the bundle
	TLSCertFile = "tls.crt" // its certificate: the kbs_cert workloads pin
)

// Config is a Trustee v0.22.0 KBS config file, limited to the keys the
// default secure Operator Verifier and Trustee configs set. The sealed-config
// checks read these keys.
type Config struct {
	HTTPServer struct {
		Sockets      []string `toml:"sockets"`
		InsecureHTTP bool     `toml:"insecure_http"`
		PrivateKey   string   `toml:"private_key,omitempty"`
		Certificate  string   `toml:"certificate,omitempty"`
	} `toml:"http_server"`
	AttestationToken struct {
		// InsecureHeaderJWK lets a token name its own signing key. Through
		// the relay, that hands the Share to anyone. Must be false.
		InsecureHeaderJWK bool     `toml:"insecure_header_jwk"`
		TrustedCertsPaths []string `toml:"trusted_certs_paths"`
	} `toml:"attestation_token"`
	AttestationService struct {
		Type        string `toml:"type"`
		TokenBroker struct {
			Signer struct {
				KeyPath  string `toml:"key_path"`
				CertPath string `toml:"cert_path"`
			} `toml:"signer"`
		} `toml:"attestation_token_broker"`
		RVPS struct {
			Type string `toml:"type"`
		} `toml:"rvps_config"`
	} `toml:"attestation_service"`
	Admin struct {
		AuthorizationMode string `toml:"authorization_mode"`
		Authentication    struct {
			BearerJWT struct {
				IdentityProviders []IdentityProvider `toml:"identity_providers"`
			} `toml:"bearer_jwt"`
		} `toml:"authentication"`
		Authorization struct {
			RegexACL struct {
				ACLs []ACL `toml:"acls"`
			} `toml:"regex_acl"`
		} `toml:"authorization"`
	} `toml:"admin"`
	StorageBackend struct {
		StorageType string `toml:"storage_type"`
		Backends    struct {
			LocalFS struct {
				DirPath string `toml:"dir_path"`
			} `toml:"local_fs"`
		} `toml:"backends"`
	} `toml:"storage_backend"`
	SessionStorageType string   `toml:"session_storage_type"`
	Plugins            []Plugin `toml:"plugins"`
}

// IdentityProvider is a trusted admin token issuer.
type IdentityProvider struct {
	PublicKeyURI string `toml:"public_key_uri"`
}

// ACL lets an admin token's role call the endpoints matching a regex.
type ACL struct {
	Role             string `toml:"role"`
	AllowedEndpoints string `toml:"allowed_endpoints"`
}

// Plugin enables a KBS plugin.
type Plugin struct {
	Name               string `toml:"name"`
	StorageBackendType string `toml:"storage_backend_type"`
}

// DefaultConfig is the default secure Operator Verifier config (spec §4
// step 2) for a run directory that KBS sees at root, listening on socket.
// Plain HTTP is deliberate (ADR 0005).
func DefaultConfig(root, socket string) Config {
	var c Config
	c.HTTPServer.Sockets = []string{socket}
	c.HTTPServer.InsecureHTTP = true
	c.AttestationToken.InsecureHeaderJWK = false
	c.AttestationToken.TrustedCertsPaths = []string{filepath.Join(root, SignerCertFile)}
	c.AttestationService.Type = "coco_as_builtin"
	c.AttestationService.TokenBroker.Signer.KeyPath = filepath.Join(root, SignerKeyFile)
	c.AttestationService.TokenBroker.Signer.CertPath = filepath.Join(root, SignerCertFile)
	c.AttestationService.RVPS.Type = "BuiltIn"
	c.Admin.AuthorizationMode = AdminAuthenticated
	c.Admin.Authentication.BearerJWT.IdentityProviders = []IdentityProvider{{PublicKeyURI: filepath.Join(root, AdminPublicKeyFile)}}
	c.Admin.Authorization.RegexACL.ACLs = []ACL{{Role: "admin", AllowedEndpoints: "^/kbs/v0/.+$"}}
	c.StorageBackend.StorageType = "LocalFs"
	c.StorageBackend.Backends.LocalFS.DirPath = filepath.Join(root, StorageDir)
	c.SessionStorageType = SessionStorageMemory
	c.Plugins = []Plugin{{Name: "resource", StorageBackendType: "kvstorage"}}
	return c
}

// DefaultTrusteeConfig is the default secure Trustee config (spec §7) for a
// published tree that KBS sees at root. It is the Operator Verifier's,
// except that KBS serves HTTPS on every interface with Trustee's sealed key.
// The storage backend is the published tree, so KBS starts from the sealed
// resource policy, resources and reference values; sessions stay in memory.
func DefaultTrusteeConfig(root string) Config {
	c := DefaultConfig(root, "0.0.0.0:8080")
	c.HTTPServer.InsecureHTTP = false
	c.HTTPServer.PrivateKey = filepath.Join(root, TLSKeyFile)
	c.HTTPServer.Certificate = filepath.Join(root, TLSCertFile)
	return c
}

// CheckSecure refuses a config whose tokens may name their own signing key
// or whose admin API is open. The relay reaches every KBS endpoint, so either
// would let the relay holder take the Share or rewrite the resource policy.
func CheckSecure(c Config) error {
	var errs []error
	if c.AttestationToken.InsecureHeaderJWK {
		errs = append(errs, errors.New("[attestation_token] insecure_header_jwk is true"))
	}
	if c.Admin.AuthorizationMode != AdminAuthenticated {
		errs = append(errs, errors.New("[admin] authorization_mode is not "+AdminAuthenticated))
	}
	return errors.Join(errs...)
}

// TrusteeRoot is where the example Trustee CVM publishes the unsealed tree
// (the Bootstrap Helper's --out) and where Trustee reads it.
const TrusteeRoot = "/trustee/config"

// KBSDefaultResourcePolicy is the resource policy KBS installs when its
// storage holds none: Trustee v0.22.0 kbs/sample_policies/default.rego
// (commit 512fed65642015b849f38fb13bfdec7806639987), byte for byte. It
// releases every resource to any attested TEE that isn't the sample one.
//
//go:embed kbs-default-resource-policy.rego
var KBSDefaultResourcePolicy string

// CheckSealedConfig runs the sealed-config checks (spec §3) on the Trustee
// config tree in dir, as Trustee will see it at root. `seal` runs them
// before encrypting, and the Bootstrap Helper again before publishing,
// because a bundle sealed with stock age skipped them.
//
// The tree's paths and values are plaintext metadata (spec §0.6), and the
// helper's error reaches stderr and the audit records. So each check fails
// with a fixed reason that names the check, never a value from the tree.
func CheckSealedConfig(dir, root string) error {
	tree, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open Trustee config tree: %w", err)
	}
	defer tree.Close()
	b, err := tree.ReadFile(ConfigFile)
	if err != nil {
		return errors.New("KBS config: " + errNotInTree.Error())
	}
	var c Config
	if err := toml.Unmarshal(b, &c); err != nil {
		return errors.New("KBS config is not valid TOML")
	}
	var insecureHTTP, sessions error
	if c.HTTPServer.InsecureHTTP {
		insecureHTTP = errors.New("[http_server] insecure_http is true")
	}
	// Sessions elsewhere would put RCAR state on the published tree or
	// outside the CVM (spec §7).
	if c.SessionStorageType != SessionStorageMemory {
		sessions = errors.New("session_storage_type is not " + SessionStorageMemory)
	}
	return errors.Join(CheckSecure(c), insecureHTTP, sessions, checkSigner(tree, root, c), checkResourcePolicy(tree, root, c),
		checkTLS(tree, root, c))
}

// clusterSuffixes are DNS suffixes that no public CA certifies: Kubernetes
// Service names, mDNS (which holds the default cluster.local), and ICANN's
// private-use TLD.
var clusterSuffixes = []string{".svc", ".local", ".internal"}

// checkTLS requires Trustee's HTTPS key and certificate in the tree, as a
// matching pair whose certificate is a leaf naming only cluster-internal
// hosts. Workloads add the certificate to their system CAs as kbs_cert
// (spec §1), so a name that a public CA would certify lets that CA's
// customers impersonate Trustee. The guest's rustls refuses a CA
// certificate as a server's own.
func checkTLS(tree *os.Root, root string, c Config) error {
	keyPEM, keyErr := readInTree(tree, root, c.HTTPServer.PrivateKey)
	certPEM, certErr := readInTree(tree, root, c.HTTPServer.Certificate)
	if err := errors.Join(wrapErr("[http_server] private_key", keyErr), wrapErr("[http_server] certificate", certErr)); err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("Trustee TLS key and certificate are not a matching PEM pair")
	}
	cert := pair.Leaf // X509KeyPair parses it (Go 1.23 and later)
	var errs []error
	if cert.IsCA {
		errs = append(errs, errors.New("Trustee TLS certificate is a CA certificate, which the guest refuses as a server certificate"))
	}
	if len(cert.DNSNames)+len(cert.IPAddresses) == 0 {
		errs = append(errs, errors.New("Trustee TLS certificate names no DNS name or IP address"))
	} else if !clusterInternal(cert) {
		errs = append(errs, errors.New("Trustee TLS certificate names a host outside the cluster: "+
			"use DNS names under .svc, .local or .internal, and private IP addresses"))
	}
	return errors.Join(errs...)
}

// clusterInternal reports whether every host the certificate names is one
// that no public CA certifies.
func clusterInternal(cert *x509.Certificate) bool {
	for _, name := range cert.DNSNames {
		if !slices.ContainsFunc(clusterSuffixes, func(s string) bool { return strings.HasSuffix(name, s) }) {
			return false
		}
	}
	for _, ip := range cert.IPAddresses {
		if !ip.IsPrivate() {
			return false
		}
	}
	return true
}

// SessionStorageMemory is KBS's in-memory session storage.
const SessionStorageMemory = "Memory"

// checkSigner requires the AS token signer's key and certificate in the
// tree, and KBS to trust that certificate. Otherwise KBS verifies no token.
func checkSigner(tree *os.Root, root string, c Config) error {
	s := c.AttestationService.TokenBroker.Signer
	_, keyErr := readInTree(tree, root, s.KeyPath)
	_, certErr := readInTree(tree, root, s.CertPath)
	var untrusted error
	if !slices.Contains(c.AttestationToken.TrustedCertsPaths, s.CertPath) {
		untrusted = errors.New("[attestation_token] trusted_certs_paths does not list the AS signer certificate")
	}
	return errors.Join(wrapErr("AS signer key", keyErr), wrapErr("AS signer certificate", certErr), untrusted)
}

// checkResourcePolicy requires the resource policy at the storage backend's
// exact policy key, non-empty and not KBS's built-in default. KBS installs
// that default when the key is missing.
func checkResourcePolicy(tree *os.Root, root string, c Config) error {
	if c.StorageBackend.StorageType != "LocalFs" {
		return errors.New("[storage_backend] storage_type is not LocalFs: KBS would not read the sealed resource policy")
	}
	path := filepath.Join(c.StorageBackend.Backends.LocalFS.DirPath, "kbs", "resource-policy.rego")
	policy, err := readInTree(tree, root, path)
	if err != nil {
		return wrapErr("resource policy", err)
	}
	code := policyCode(string(policy))
	if code == "" {
		return errors.New("resource policy is empty")
	}
	if code == policyCode(KBSDefaultResourcePolicy) {
		return errors.New("resource policy is KBS's built-in default")
	}
	return nil
}

// policyCode is a Rego policy without comment lines or whitespace, so a copy
// of the default with other comments or layout still compares equal.
// ponytail: a rewritten but equivalent default still passes; compare parsed
// Rego if that matters.
func policyCode(policy string) string {
	var code strings.Builder
	for line := range strings.Lines(policy) {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code.WriteString(strings.Join(strings.Fields(line), ""))
		}
	}
	return code.String()
}

// readInTree reads the file that Trustee, seeing the tree at root, finds at
// path. A path outside root is not in the sealed tree. Its errors leave out
// path, a value from the tree.
func readInTree(tree *os.Root, root, path string) ([]byte, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, errOutsideTree
	}
	b, err := tree.ReadFile(rel)
	if err != nil {
		return nil, errNotInTree
	}
	return b, nil
}

var (
	errOutsideTree = errors.New("its path is outside the sealed tree")
	errNotInTree   = errors.New("no readable file in the sealed tree")
)

// wrapErr names what err is about; nil stays nil.
func wrapErr(what string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}
