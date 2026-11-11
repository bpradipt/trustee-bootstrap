package cli_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
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
	out         string                  // where Trustee sees the unsealed tree (`seal --root`)
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

	trustee := filepath.Join(t.TempDir(), "trustee")
	bundlePath := filepath.Join(t.TempDir(), "bundle.age")
	digest := strings.TrimSpace(mustRun(t, "seal", "--manifest", manifestPath, "--output", bundlePath,
		"--root", trustee, trusteetest.Tree(t, trustee)))
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if digest != ceremony.SHA256Hex(bundle) {
		t.Errorf("seal printed %q, want the bundle's SHA-256", digest)
	}

	f := unlockFixture{manifest: manifest, bundle: bundle, ceremonyDir: ceremonyDir, out: trustee}
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
	out := f.out
	h, err := helper.New(f.manifest, ceremony.SHA256Hex(f.manifest), f.bundle, helper.Output{Dir: out, UID: os.Getuid(), GID: os.Getgid()}, fakeCDH(t, payloads...), audit.New(io.Discard))
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
	got, err := os.ReadFile(filepath.Join(out, verifier.ResourcePolicyPath))
	if err != nil || string(got) != trusteetest.ResourcePolicy {
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

// A tree whose Sealed Bundle would pass the 1 MiB size cap gets no bundle.
func TestSealRefusesABundleOverTheSizeCap(t *testing.T) {
	ceremonyDir := t.TempDir()
	mustRun(t, "ceremony", "split", "--threshold", "2", "--holders", "alice,bob", "--out-dir", ceremonyDir)
	tree := trusteetest.Tree(t, verifier.TrusteeRoot)
	if err := os.WriteFile(filepath.Join(tree, "big"), make([]byte, seal.MaxSize), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "b.age")
	if _, err := run(t, "seal", "--manifest", filepath.Join(ceremonyDir, cli.ManifestFile), "--output", bundle, tree); err == nil {
		t.Fatal("seal sealed a tree over the size cap")
	}
	if _, err := os.Stat(bundle); !os.IsNotExist(err) {
		t.Error("seal wrote a bundle")
	}
}

// AT-27: `seal` runs the sealed-config checks and writes no bundle for a tree
// that fails one. With no --root, Trustee sees the tree at /trustee/config.
func TestSealRefusesEachSealedConfigViolation(t *testing.T) {
	ceremonyDir := t.TempDir()
	mustRun(t, "ceremony", "split", "--threshold", "2", "--holders", "alice,bob", "--out-dir", ceremonyDir)
	manifest := filepath.Join(ceremonyDir, cli.ManifestFile)
	mustRun(t, "seal", "--manifest", manifest, "--output", filepath.Join(t.TempDir(), "b.age"), trusteetest.Tree(t, verifier.TrusteeRoot))
	for _, v := range trusteetest.Violations {
		t.Run(v.Name, func(t *testing.T) {
			tree := trusteetest.Tree(t, verifier.TrusteeRoot)
			v.Apply(t, tree)
			bundle := filepath.Join(t.TempDir(), "b.age")
			if _, err := run(t, "seal", "--manifest", manifest, "--output", bundle, tree); err == nil || !strings.Contains(err.Error(), v.Want) {
				t.Fatalf("seal = %v, want the %s check to fail", err, v.Want)
			}
			if _, err := os.Stat(bundle); !os.IsNotExist(err) {
				t.Error("seal wrote a bundle")
			}
		})
	}
}
