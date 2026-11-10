package verifier_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

func TestDefaultConfigIsSecure(t *testing.T) {
	c := verifier.DefaultConfig("/etc/kbs", "127.0.0.1:8080")
	if err := verifier.CheckSecure(c); err != nil {
		t.Fatalf("CheckSecure(DefaultConfig) = %v", err)
	}
	if !c.HTTPServer.InsecureHTTP || c.SessionStorageType != "Memory" {
		t.Errorf("DefaultConfig = %+v, want plain HTTP and in-memory sessions", c)
	}
	if want := []string{"/etc/kbs/as-signer.crt"}; !slices.Equal(c.AttestationToken.TrustedCertsPaths, want) ||
		c.AttestationService.TokenBroker.Signer.CertPath != want[0] {
		t.Errorf("KBS trusts %v, the AS signs with %s; want both %s",
			c.AttestationToken.TrustedCertsPaths, c.AttestationService.TokenBroker.Signer.CertPath, want[0])
	}

	jwk := c
	jwk.AttestationToken.InsecureHeaderJWK = true
	open := c
	open.Admin.AuthorizationMode = "InsecureAllowAll"
	for name, tt := range map[string]struct {
		c    verifier.Config
		want []string
	}{
		"insecure_header_jwk": {jwk, []string{"insecure_header_jwk"}},
		"InsecureAllowAll":    {open, []string{`"InsecureAllowAll"`}},
		"both":                {verifier.Config{}, []string{"insecure_header_jwk", "authorization_mode"}},
	} {
		if name == "both" {
			tt.c = open
			tt.c.AttestationToken.InsecureHeaderJWK = true
		}
		err := verifier.CheckSecure(tt.c)
		for _, w := range tt.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("%s: CheckSecure = %v, want it to name %s", name, err, w)
			}
		}
	}
}

func TestDefaultTrusteeConfig(t *testing.T) {
	c := verifier.DefaultTrusteeConfig("/trustee/config")
	if err := verifier.CheckSecure(c); err != nil {
		t.Fatalf("CheckSecure(DefaultTrusteeConfig) = %v", err)
	}
	if c.HTTPServer.InsecureHTTP || c.HTTPServer.PrivateKey != "/trustee/config/tls.key" ||
		c.HTTPServer.Certificate != "/trustee/config/tls.crt" {
		t.Errorf("http_server = %+v, want HTTPS with Trustee's sealed key", c.HTTPServer)
	}
	if c.StorageBackend.Backends.LocalFS.DirPath != "/trustee/config/storage" || c.SessionStorageType != "Memory" {
		t.Errorf("storage = %+v, sessions %q; want the published tree and in-memory sessions",
			c.StorageBackend, c.SessionStorageType)
	}

	// The example config is the default, key for key.
	var example verifier.Config
	md, err := toml.DecodeFile("../../deploy/examples/trustee-config/kbs.toml", &example)
	if err != nil {
		t.Fatal(err)
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		t.Errorf("the example config sets keys the default does not: %v", extra)
	}
	if !reflect.DeepEqual(example, c) {
		t.Errorf("example config = %+v\nwant %+v", example, c)
	}
}

// answering is a KBS that answers the readiness probe once the fake
// executable has recorded its arguments.
type answering struct{ executable string }

func (a answering) RoundTrip(*http.Request) (*http.Response, error) {
	if _, err := os.Stat(a.executable + ".args"); err != nil {
		return nil, errors.New("connection refused")
	}
	return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
}

// silent is a KBS that never answers.
type silent struct{}

func (silent) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// fakeExecutable writes a shell script that records its arguments in
// <path>.args and then runs body.
func fakeExecutable(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.tmp\" && mv \"$0.tmp\" \"$0.args\"\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordedArgs(t *testing.T, executable string) []string {
	t.Helper()
	b, err := os.ReadFile(executable + ".args")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func runtime(rt http.RoundTripper, engine string) verifier.Runtime {
	var loopback memnet.Network
	return verifier.Runtime{Engine: engine, Listen: loopback.Listen, Client: &http.Client{Transport: rt}}
}

var opts = verifier.Options{
	ResourcePolicy:  "package policy\n",
	ReferenceValues: map[string][]string{"trusted_aks": {"AK"}},
	SharePayload:    []byte(`{"index":1}`),
}

func TestStartKBSBinary(t *testing.T) {
	runDirs := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	kbs := fakeExecutable(t, "kbs", "exec sleep 60")
	o := opts
	o.KBSBinary = kbs

	addr, stop, err := runtime(answering{kbs}, "podman").Start(t.Context(), "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:0" {
		t.Errorf("addr = %s, want the reserved 127.0.0.1 address", addr)
	}
	args := recordedArgs(t, kbs)
	dir := filepath.Dir(args[1])
	if len(args) != 2 || args[0] != "--config-file" || filepath.Dir(dir) != runDirs {
		t.Fatalf("kbs args = %q, want --config-file <run dir in XDG_RUNTIME_DIR>/kbs.toml", args)
	}
	var got verifier.Config
	if _, err := toml.DecodeFile(args[1], &got); err != nil {
		t.Fatal(err)
	}
	if want := verifier.DefaultConfig(dir, addr); !reflect.DeepEqual(got, want) {
		t.Errorf("kbs.toml = %+v\nwant %+v", got, want)
	}
	assertRunDir(t, dir)

	stop()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("run directory survived stop: %v", err)
	}
}

func assertRunDir(t *testing.T, dir string) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", name, info.Mode().Perm())
		}
		b, _ := os.ReadFile(path)
		return b
	}
	block, _ := pem.Decode(read(verifier.AdminPublicKeyFile))
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Errorf("admin key: %v", err)
	} else if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("admin key is %T, want Ed25519", pub)
	}
	assertSigner(t, read(verifier.SignerKeyFile), read(verifier.SignerCertFile))
	storage := filepath.Join(verifier.StorageDir)
	// KBS v0.22.0 installs its built-in default policy unless this exact
	// key holds one.
	if got := string(read(filepath.Join(storage, "kbs", "resource-policy.rego"))); got != opts.ResourcePolicy {
		t.Errorf("resource policy = %q", got)
	}
	if got := string(read(filepath.Join(storage, "repository", `trustee-bootstrap\x2Fshare\x2Fcurrent`))); got != string(opts.SharePayload) {
		t.Errorf("Share payload resource = %q", got)
	}
	var rv struct {
		Version, Name, Expiration string
		Value                     []string
	}
	if err := json.Unmarshal(read(filepath.Join(storage, "reference_value", "trusted_aks")), &rv); err != nil {
		t.Fatal(err)
	}
	if rv.Version != "0.1.0" || rv.Name != "trusted_aks" || !slices.Equal(rv.Value, []string{"AK"}) || len(rv.Expiration) != 20 {
		t.Errorf("reference value = %+v", rv)
	}
}

// assertSigner checks that the AS signer's certificate is self-signed for
// its key, so KBS can verify the AS's tokens against it.
func assertSigner(t *testing.T, keyPEM, certPEM []byte) {
	t.Helper()
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("AS signer key: %v", err)
	}
	cb, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("AS signer cert: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey.(*ecdsa.PublicKey)) {
		t.Error("AS signer cert is not for its key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("AS signer cert does not verify against itself: %v", err)
	}
}

func TestStartContainer(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	engine := fakeExecutable(t, "podman", "exec sleep 60")

	addr, stop, err := runtime(answering{engine}, engine).Start(t.Context(), "127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	args := recordedArgs(t, engine)
	dir := strings.TrimSuffix(args[5], ":/etc/kbs:Z")
	want := []string{"run", "--rm", "-p", addr + ":8080", "-v", dir + ":/etc/kbs:Z", verifier.Image,
		"/usr/local/bin/kbs", "--config-file", "/etc/kbs/kbs.toml"}
	if !slices.Equal(args, want) {
		t.Fatalf("engine args = %q\nwant %q", args, want)
	}
	var got verifier.Config
	if _, err := toml.DecodeFile(filepath.Join(dir, verifier.ConfigFile), &got); err != nil {
		t.Fatal(err)
	}
	if want := verifier.DefaultConfig("/etc/kbs", "0.0.0.0:8080"); !reflect.DeepEqual(got, want) {
		t.Errorf("kbs.toml = %+v\nwant %+v", got, want)
	}
}

func TestStartReportsKBSFailure(t *testing.T) {
	runDirs := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runDirs)
	o := opts
	o.KBSBinary = fakeExecutable(t, "kbs", "echo 'bad config' >&2; exit 1")

	_, _, err := runtime(silent{}, "").Start(t.Context(), "127.0.0.1:0", o)
	if err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Errorf("Start = %v, want KBS's output", err)
	}
	if entries, _ := os.ReadDir(runDirs); len(entries) != 0 {
		t.Errorf("run directory left behind: %v", entries)
	}
}

func TestDefaultEngine(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if got := verifier.DefaultEngine(); got != "docker" {
		t.Errorf("without podman: %s, want docker", got)
	}
	if err := os.WriteFile(filepath.Join(bin, "podman"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := verifier.DefaultEngine(); got != "podman" {
		t.Errorf("with podman: %s, want podman", got)
	}
}
