package cli_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
)

// run executes the command tree with args and returns its stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := cli.NewTrusteeBootstrapCmd()
	cmd.SetOut(&out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

func readJSON(t *testing.T, path string, v any) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
	return b
}

// sha256Hex is the digest form of `seal`'s output and --manifest-sha256.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// serveInProcess is an http.RoundTripper that hands each request to a handler.
type serveInProcess struct{ http.Handler }

func (s serveInProcess) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// fakeCDH serves one Share payload per get-resource call, in order, in process.
func fakeCDH(t *testing.T, payloads ...ceremony.SharePayload) helper.CDH {
	t.Helper()
	cdh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != helper.ShareResourcePath || len(payloads) == 0 {
			http.NotFound(w, r)
			return
		}
		p := payloads[0]
		payloads = payloads[1:]
		if err := json.NewEncoder(w).Encode(p); err != nil {
			t.Error(err)
		}
	})
	return helper.CDH{URL: "http://127.0.0.1:8006", Client: &http.Client{Transport: serveInProcess{cdh}}}
}

type unlockFixture struct {
	manifest    []byte
	bundle      []byte
	payloads    []ceremony.SharePayload // alice, bob, carol
	ceremonyDir string                  // holds <holder>.share
}

// keyCeremonyAndSeal plays the Ceremony Authority (`ceremony split` for
// 2-of-3) and the Infrastructure Operator (`seal`), then builds the Share
// payloads each Operator Verifier would serve.
func keyCeremonyAndSeal(t *testing.T) unlockFixture {
	t.Helper()
	ceremonyDir := t.TempDir()
	out := mustRun(t, "ceremony", "split", "--threshold", "2", "--holders", "alice,bob,carol", "--out-dir", ceremonyDir)
	var m ceremony.Manifest
	manifestPath := filepath.Join(ceremonyDir, cli.ManifestFile)
	manifest := readJSON(t, manifestPath, &m)
	if !strings.Contains(out, m.KeyID) || !strings.Contains(out, m.Recipient) {
		t.Errorf("split output %q lacks key_id or recipient", out)
	}
	assertNoIdentityOnDisk(t, ceremonyDir)

	config := t.TempDir()
	if err := os.MkdirAll(filepath.Join(config, "policy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "kbs-config.toml"), []byte("insecure_http = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config, "policy", "resource.rego"), []byte("package policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "bundle.age")
	digest := strings.TrimSpace(mustRun(t, "seal", "--manifest", manifestPath, "--output", bundlePath, config))
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256Hex(bundle) {
		t.Errorf("seal printed %q, want the bundle's SHA-256", digest)
	}

	f := unlockFixture{manifest: manifest, bundle: bundle, ceremonyDir: ceremonyDir}
	for _, holder := range []string{"alice", "bob", "carol"} {
		var share ceremony.ShareFile
		readJSON(t, filepath.Join(ceremonyDir, holder+".share"), &share)
		f.payloads = append(f.payloads, ceremony.SharePayload{ShareFile: share, BundleSHA256: digest})
	}
	return f
}

func assertNoIdentityOnDisk(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("split wrote %d files, want ceremony.json and 3 Share files", len(entries))
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
			t.Errorf("%s holds the age identity", e.Name())
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(e.Name(), ".share") && info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", e.Name(), info.Mode().Perm())
		}
	}
}

func newHelper(t *testing.T, f unlockFixture, payloads ...ceremony.SharePayload) (*helper.Helper, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "trustee")
	h, err := helper.New(f.manifest, sha256Hex(f.manifest), f.bundle, out, fakeCDH(t, payloads...))
	if err != nil {
		t.Fatal(err)
	}
	return h, out
}

// AT-13, in-process.
func TestUnlockCeremonyTwoOfThreeUnlocks(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	h, out := newHelper(t, f, f.payloads[0], f.payloads[2])

	if published, err := h.CollectShare(t.Context()); err != nil || published {
		t.Fatalf("first Share: published = %v, err = %v", published, err)
	}
	if published, err := h.CollectShare(t.Context()); err != nil || !published {
		t.Fatalf("second Share: published = %v, err = %v", published, err)
	}
	got, err := os.ReadFile(filepath.Join(out, "policy", "resource.rego"))
	if err != nil || string(got) != "package policy\n" {
		t.Fatalf("published resource.rego = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(out, helper.CompletionMarker)); err != nil {
		t.Errorf("completion marker: %v", err)
	}
}

// AT-12, in-process.
func TestUnlockCeremonyOneShareStaysLocked(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	h, out := newHelper(t, f, f.payloads[1])

	if published, err := h.CollectShare(t.Context()); err != nil || published {
		t.Fatalf("published = %v, err = %v", published, err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("tree published with one Share")
	}
}

// The seal output is a standard age file: the identity the Shares rebuild
// decrypts it with the age library, as `age -d -i` would.
func TestSealOutputIsStandardAge(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	id, err := ceremony.Combine([][]byte{f.payloads[0].Share, f.payloads[1].Share})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(bytes.NewReader(f.bundle), id); err != nil {
		t.Fatalf("age cannot decrypt the Sealed Bundle: %v", err)
	}
}

func TestSplitRefusesToOverwriteShares(t *testing.T) {
	dir := t.TempDir()
	args := []string{"ceremony", "split", "--threshold", "2", "--holders", "alice,bob", "--out-dir", dir}
	mustRun(t, args...)
	if _, err := run(t, args...); err == nil {
		t.Fatal("second split overwrote the first ceremony's files")
	}
}

func TestSealRejectsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	_, err := run(t, "seal", "--manifest", filepath.Join(dir, "none.json"), "--output", filepath.Join(dir, "b.age"), dir)
	if err == nil {
		t.Fatal("seal accepted a missing manifest")
	}
}
