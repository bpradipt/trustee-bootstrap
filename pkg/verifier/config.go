package verifier

import (
	"errors"
	"fmt"
	"path/filepath"
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
	c.SessionStorageType = "Memory"
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
		errs = append(errs, fmt.Errorf("[admin] authorization_mode is %q, not %s", c.Admin.AuthorizationMode, AdminAuthenticated))
	}
	return errors.Join(errs...)
}
