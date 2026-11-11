package helper_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

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

// ceremonyFixture runs a 2-of-3 Key Ceremony and seals a Trustee config
// tree that Trustee will see at out.
func ceremonyFixture(t *testing.T) (manifest, bundle []byte, payloads []ceremony.SharePayload, out string) {
	t.Helper()
	out = filepath.Join(t.TempDir(), "trustee")
	return sealedFixture(t, trusteetest.Tree(t, out), out)
}

// sealedFixture runs a 2-of-3 Key Ceremony and seals tree with the age
// library, as stock age would: without the sealed-config checks.
func sealedFixture(t *testing.T, tree, out string) (manifest, bundle []byte, payloads []ceremony.SharePayload, _ string) {
	t.Helper()
	m, files, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := seal.Seal(&b, tree, m.Recipient); err != nil {
		t.Fatal(err)
	}
	manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		payloads = append(payloads, ceremony.SharePayload{ShareFile: f, BundleSHA256: ceremony.SHA256Hex(b.Bytes())})
	}
	return manifest, b.Bytes(), payloads, out
}

// discard drops the audit records of tests that do not read them.
var discard = slog.New(slog.DiscardHandler)

// owned is out, owned by the test's own UID and GID: the only owner a
// test that is not root can hand the tree to.
func owned(out string) helper.Output {
	return helper.Output{Dir: out, UID: os.Getuid(), GID: os.Getgid()}
}

func newHelper(t *testing.T, manifest, bundle []byte, out string, cdh helper.CDH) *helper.Helper {
	t.Helper()
	h, err := helper.New(manifest, ceremony.SHA256Hex(manifest), bundle, owned(out), cdh, discard)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// AT-27: a bundle sealed with stock age skipped the sealed-config checks.
// The helper runs them before publishing, so each violation fails the
// unlock, and neither the tree nor its staging directory remains.
func TestSealedConfigViolationPublishesNothing(t *testing.T) {
	for _, v := range trusteetest.Violations {
		t.Run(v.Name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "trustee")
			tree := trusteetest.Tree(t, out)
			v.Apply(t, tree)
			manifest, bundle, payloads, _ := sealedFixture(t, tree, out)
			h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))

			if _, err := h.CollectShare(t.Context()); err != nil {
				t.Fatal(err)
			}
			published, err := h.CollectShare(t.Context())
			if published || err == nil || !strings.Contains(err.Error(), v.Want) {
				t.Fatalf("CollectShare = %v, %v; want the %s check to fail", published, err, v.Want)
			}
			if got := h.Status().State; got != helper.StateFailed {
				t.Errorf("state = %s, want %s", got, helper.StateFailed)
			}
			for _, dir := range []string{out, out + ".staging"} {
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Errorf("%s exists after a failed unlock", dir)
				}
			}
		})
	}
}

// AT-14: a tree that passes the checks but carries a symlink fails in
// extraction, and the partly extracted staging directory is wiped.
func TestBoobyTrappedTreePublishesNothing(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trustee")
	tree := trusteetest.Tree(t, out)
	if err := os.Symlink("/etc/passwd", filepath.Join(tree, "zz-link")); err != nil {
		t.Fatal(err)
	}
	manifest, bundle, payloads, _ := sealedFixture(t, tree, out)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))

	if _, err := h.CollectShare(t.Context()); err != nil {
		t.Fatal(err)
	}
	published, err := h.CollectShare(t.Context())
	if published || err == nil || !strings.Contains(err.Error(), "entry type not allowed") {
		t.Fatalf("CollectShare = %v, %v; want the symlink refused", published, err)
	}
	if strings.Contains(err.Error(), "zz-link") {
		t.Errorf("CollectShare error %q names the tar entry", err)
	}
	for _, dir := range []string{out, out + ".staging"} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s exists after a failed unlock", dir)
		}
	}
}

func TestTwoSharesPublishTree(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[2]))

	for i, want := range []bool{false, true} {
		published, err := h.CollectShare(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if published != want {
			t.Fatalf("CollectShare %d: published = %v, want %v", i+1, published, want)
		}
	}
	for _, name := range []string{verifier.ConfigFile, verifier.ResourcePolicyPath, helper.CompletionMarker} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("published tree: %v", err)
		}
	}
	if _, err := os.Stat(out + ".staging"); !os.IsNotExist(err) {
		t.Error("staging directory left behind")
	}
}

func TestOneShareStaysLocked(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[1]))

	published, err := h.CollectShare(t.Context())
	if err != nil || published {
		t.Fatalf("CollectShare = %v, %v; want locked", published, err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("tree published with one Share")
	}
}

// AT-07: the same index delivered twice is counted once.
func TestSameIndexTwiceCountedOnce(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[0], payloads[2]))

	if published, err := h.CollectShare(t.Context()); err != nil || published {
		t.Fatalf("first Share: CollectShare = %v, %v; want counted, locked", published, err)
	}
	if published, err := h.CollectShare(t.Context()); err == nil || published {
		t.Fatalf("repeated index: CollectShare = %v, %v; want rejected", published, err)
	}
	st := h.Status()
	if !slices.Equal(st.Accepted, []int{1}) || !slices.Equal(st.Rejected, []int{1}) {
		t.Fatalf("status accepted %v rejected %v; want [1] and [1]", st.Accepted, st.Rejected)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("tree published with one distinct Share")
	}
	if published, err := h.CollectShare(t.Context()); err != nil || !published {
		t.Fatalf("second distinct Share: CollectShare = %v, %v; want published", published, err)
	}
}

// AT-08 and the other COLLECTING checks: a rejected payload is not counted,
// and its index is reported.
func TestBadShareRejectedAndReported(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(p *ceremony.SharePayload)
		index  int
	}{
		{
			name:   "Share does not match its commitment",
			mutate: func(p *ceremony.SharePayload) { p.Share = slices.Clone(p.Share); p.Share[0] ^= 1 },
			index:  1,
		},
		{name: "index not in manifest", mutate: func(p *ceremony.SharePayload) { p.Index = 4 }, index: 4},
		{name: "other key_id", mutate: func(p *ceremony.SharePayload) { p.KeyID = "00000000000000000000000000000000" }, index: 1},
		// AT-09 and AT-10: the host mounts a bundle of its own, or an older
		// one, so the bundle_sha256 that operators approved names another.
		{name: "bundle_sha256 names another bundle", mutate: func(p *ceremony.SharePayload) { p.BundleSHA256 = ceremony.SHA256Hex([]byte("older")) }, index: 1},
		{name: "no bundle_sha256", mutate: func(p *ceremony.SharePayload) { p.BundleSHA256 = "" }, index: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, bundle, payloads, out := ceremonyFixture(t)
			bad := payloads[0]
			tt.mutate(&bad)
			h := newHelper(t, manifest, bundle, out, fakeCDH(t, bad, payloads[1]))

			if published, err := h.CollectShare(t.Context()); err == nil || published {
				t.Fatalf("CollectShare = %v, %v; want rejected", published, err)
			}
			st := h.Status()
			if len(st.Accepted) != 0 || !slices.Equal(st.Rejected, []int{tt.index}) {
				t.Fatalf("status accepted %v rejected %v; want [] and [%d]", st.Accepted, st.Rejected, tt.index)
			}
			if published, err := h.CollectShare(t.Context()); err != nil || published {
				t.Fatalf("one good Share after a rejected one: CollectShare = %v, %v; want locked", published, err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("rejected payload was counted")
			}
		})
	}
}

func TestRejectedIndexReportedOnce(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	bad := payloads[1]
	bad.Index = 7
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, bad, bad))
	for range 2 {
		if _, err := h.CollectShare(t.Context()); err == nil {
			t.Fatal("CollectShare accepted index 7")
		}
	}
	if got := h.Status().Rejected; !slices.Equal(got, []int{7}) {
		t.Fatalf("rejected = %v, want [7]", got)
	}
}

func TestNewRejectsInvalidManifest(t *testing.T) {
	m, _, err := ceremony.Split(2, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	m.Threshold = 3
	manifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := helper.New(manifest, ceremony.SHA256Hex(manifest), nil, owned(t.TempDir()), fakeCDH(t), discard); err == nil {
		t.Fatal("New accepted threshold 3 with 2 shares")
	}
}

// AT-11: the helper fails in LOCKED when the mounted Ceremony Manifest is not
// the one --manifest-sha256 pins, or when the host dropped the flag.
func TestNewRejectsManifestDigestMismatch(t *testing.T) {
	manifest, bundle, _, _ := ceremonyFixture(t)
	other, _, _, _ := ceremonyFixture(t)
	tests := []struct {
		name   string
		pinned string
	}{
		{"swapped ceremony.json", ceremony.SHA256Hex(other)},
		{"--manifest-sha256 dropped", ""},
		{"digest with a prefix", "sha256:" + ceremony.SHA256Hex(manifest)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := helper.New(manifest, tt.pinned, bundle, owned(t.TempDir()), fakeCDH(t), discard)
			if err == nil || !strings.Contains(err.Error(), "does not match --manifest-sha256") {
				t.Fatalf("New = %v, want a manifest digest mismatch", err)
			}
		})
	}
}

func TestCDHErrorIsReturned(t *testing.T) {
	manifest, bundle, _, out := ceremonyFixture(t)
	h := newHelper(t, manifest, bundle, out, fakeCDH(t))
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Fatal("CollectShare succeeded when the CDH returned 404")
	}
}

// The helper reads at most 64 KiB of the CDH's answer: a Share payload is a
// few hundred bytes, and the CDH relays what the Operator Verifier sends.
func TestCDHAnswerIsCapped(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	body, err := json.Marshal(payloads[0])
	if err != nil {
		t.Fatal(err)
	}
	padded := append(bytes.Repeat([]byte(" "), 65536), body...) // valid JSON, over the cap
	cdh := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(padded); err != nil {
			t.Error(err)
		}
	})
	h := newHelper(t, manifest, bundle, out, helper.CDH{URL: "http://127.0.0.1:8006", Client: &http.Client{Transport: serveInProcess{cdh}}})
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Fatal("CollectShare read a CDH answer over the cap")
	}
	if got := h.Status().Accepted; len(got) != 0 {
		t.Errorf("accepted = %v, want none", got)
	}
}

func TestNewRejectsBadManifest(t *testing.T) {
	if _, err := helper.New([]byte("{"), ceremony.SHA256Hex([]byte("{")), nil, owned(t.TempDir()), fakeCDH(t), discard); err == nil {
		t.Fatal("New accepted a malformed Ceremony Manifest")
	}
}

// The published tree belongs to Trustee's UID and GID, from --owner-uid and
// --owner-gid. Only root can give a file away, so as another user the
// helper fails the unlock rather than publish a tree Trustee can't own.
func TestPublishedTreeIsTrustees(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	trustee := helper.Output{Dir: out, UID: 4242, GID: 4243}
	h, err := helper.New(manifest, ceremony.SHA256Hex(manifest), bundle, trustee, fakeCDH(t, payloads[0], payloads[1]), discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CollectShare(t.Context()); err != nil {
		t.Fatal(err)
	}
	published, err := h.CollectShare(t.Context())
	if os.Getuid() != 0 {
		if published || err == nil {
			t.Fatalf("CollectShare = %v, %v; want the chown refused", published, err)
		}
		return
	}
	if !published || err != nil {
		t.Fatalf("CollectShare = %v, %v; want the tree published", published, err)
	}
	err = filepath.WalkDir(out, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 || st.Gid != 4243 {
			t.Errorf("%s is owned by %d:%d, want 4242:4243", path, st.Uid, st.Gid)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
