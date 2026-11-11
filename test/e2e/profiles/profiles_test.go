// Package profiles runs the claim-profile evidence fixtures (AT-28) through
// the pinned Trustee KBS image, so the generated resource policy is
// evaluated by the same Rego engine (regorus 0.11.0) that KBS v0.22.0 runs
// it with. It is a test so it never ships. With -engine, it builds one
// Operator Policy that accepts every TEE type, starts the Operator Verifier
// with it, signs each fixture's EAR claims with that run's AS signer key,
// and asks for the Share. Only the matching fixtures may get it. Without
// -engine, only the engine-free checks run.
//
// testdata holds, per TEE type, the matching EAR claims, the changes that
// must be denied (wrong Init-Data, debug on, not affirming) and the claims
// whose absence must be denied (JSON pointers; no key holds '/' or '~').
// testdata/gen.py generates them from the verifier source formulas that
// docs/claim-profiles.md cites. No real hardware produced them.
package profiles

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

var engine = flag.String("engine", "", "run the fixtures through the pinned KBS image with this engine (podman or docker)")

var tees = []string{policy.TEETPM, policy.TEETDX, policy.TEESNP, policy.TEEAzSNPVTPM, policy.TEEAzTDXVTPM}

type fixture struct {
	Source   string                    `json:"source"`
	Claims   map[string]any            `json:"claims"`
	Deny     map[string]map[string]any `json:"deny"`
	Required []string                  `json:"required"`
}

func readFixture(t *testing.T, tee string) fixture {
	t.Helper()
	var f fixture
	readJSON(t, tee+".json", &f)
	return f
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// buildPolicy builds the Operator Policy for the fixtures' Init-Data and
// reference values, accepting every TEE type.
func buildPolicy(t *testing.T) policy.OperatorPolicy {
	t.Helper()
	initData, err := os.ReadFile(filepath.Join("testdata", "init-data.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var rv map[string][]any
	readJSON(t, "reference-values.json", &rv)
	m, files, err := ceremony.Split(2, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Build(policy.Input{
		InitData: initData, ReferenceValues: rv, AcceptTEE: tees, AllowUntested: true,
		BundleSHA256: strings.Repeat("ab", sha256.Size), Manifest: m, Share: files[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Each fixture's init_data claim is what the policy expects, and every
// required claim is present in the matching claims.
func TestFixturesFitPolicy(t *testing.T) {
	p := buildPolicy(t)
	for _, tee := range tees {
		f := readFixture(t, tee)
		init := lookup(f.Claims, "/submods/cpu0/ear.veraison.annotated-evidence/init_data")
		if s, ok := init.(string); !ok || !strings.Contains(p.ResourcePolicy, `evidence.init_data == "`+s+`"`) {
			t.Errorf("%s: init_data %v is not in the resource policy", tee, init)
		}
		for _, ptr := range f.Required {
			if lookup(f.Claims, ptr) == nil {
				t.Errorf("%s: required claim %s is not in the matching claims", tee, ptr)
			}
		}
	}
}

// AT-28: only the matching evidence gets a release.
func TestFixturesThroughKBS(t *testing.T) {
	if *engine == "" {
		t.Skip("needs -engine and the pinned KBS image")
	}
	p := buildPolicy(t)
	before := runDirs(t)
	rt := verifier.Runtime{Engine: *engine, Listen: net.Listen, Client: http.DefaultClient}
	addr, stop, err := rt.Start(t.Context(), "127.0.0.1:0", verifier.Options{
		ResourcePolicy: p.ResourcePolicy, ReferenceValues: p.ReferenceValues, SharePayload: []byte(`{"fixture":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	s := loadSigner(t, before)
	url := "http://" + addr + "/kbs/v0/resource/" + verifier.ShareResource
	for _, tee := range tees {
		f := readFixture(t, tee)
		t.Run(tee+"/matching", func(t *testing.T) {
			if code, body := s.get(t, url, f.Claims); code != http.StatusOK {
				t.Errorf("HTTP %d %s, want the Share", code, body)
			}
		})
		for name, changes := range f.Deny {
			claims := clone(t, f.Claims)
			for ptr, v := range changes {
				set(t, claims, ptr, v)
			}
			t.Run(tee+"/"+name, func(t *testing.T) { s.wantDeny(t, url, claims) })
		}
		for _, ptr := range f.Required {
			claims := clone(t, f.Claims)
			set(t, claims, ptr, nil)
			t.Run(tee+"/missing "+ptr, func(t *testing.T) { s.wantDeny(t, url, claims) })
		}
	}
}

// runDirs lists the Operator Verifier run directories (verifier.runtimeDir).
func runDirs(t *testing.T) []string {
	t.Helper()
	parent := os.Getenv("XDG_RUNTIME_DIR")
	if parent == "" {
		parent = "/dev/shm"
	}
	dirs, err := filepath.Glob(filepath.Join(parent, "trustee-bootstrap-verifier-*"))
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// signer is the run's AS token signer: the test stands in for the built-in
// AS, which is the only party KBS takes tokens from.
type signer struct {
	key  *ecdsa.PrivateKey
	cert []byte // DER
}

func loadSigner(t *testing.T, before []string) signer {
	t.Helper()
	var dir string
	for _, d := range runDirs(t) {
		if !slices.Contains(before, d) {
			dir = d
		}
	}
	if dir == "" {
		t.Fatal("no new Operator Verifier run directory")
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, verifier.SignerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, verifier.SignerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(certPEM)
	if kb == nil || cb == nil {
		t.Fatal("signer key or certificate is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, cert: cb.Bytes}
}

func (s signer) wantDeny(t *testing.T, url string, claims map[string]any) {
	t.Helper()
	if code, body := s.get(t, url, claims); code == http.StatusOK || !strings.Contains(body, "PolicyDeny") {
		t.Errorf("HTTP %d %s, want a PolicyDeny", code, body)
	}
}

// get asks for the resource with an EAR token carrying claims.
func (s signer) get(t *testing.T, url string, claims map[string]any) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token(t, claims))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return resp.StatusCode, string(b)
}

// token signs claims as the AS does: ES256, with the signer's key and
// certificate in the header's jwk (x5c).
func (s signer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	now := time.Now().Unix()
	claims = clone(t, claims)
	claims["iat"], claims["exp"] = now, now+600
	pub, err := s.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	xy := pub.Bytes() // 0x04 || X || Y
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256", "alg": "ES256",
		"x":   base64.RawURLEncoding.EncodeToString(xy[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(xy[33:]),
		"x5c": []string{base64.StdEncoding.EncodeToString(s.cert)},
	}
	in := encode(t, map[string]any{"alg": "ES256", "typ": "JWT", "jwk": jwk}) + "." + encode(t, claims)
	d := sha256.Sum256([]byte(in))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
}

func encode(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// lookup returns the value at a JSON pointer, or nil.
func lookup(m map[string]any, ptr string) any {
	var v any = m
	for _, k := range strings.Split(ptr, "/")[1:] {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = obj[k]
	}
	return v
}

// set replaces the value at a JSON pointer; nil deletes it. The claim must
// exist, so a typo in a fixture fails instead of passing as a denial.
func set(t *testing.T, m map[string]any, ptr string, v any) {
	t.Helper()
	i := strings.LastIndex(ptr, "/")
	parent, ok := lookup(m, ptr[:i]).(map[string]any)
	key := ptr[i+1:]
	if _, found := parent[key]; !ok || !found {
		t.Fatalf("no claim at %s", ptr)
	}
	if v == nil {
		delete(parent, key)
		return
	}
	parent[key] = v
}
