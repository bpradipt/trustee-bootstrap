package helper_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
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

// ceremonyFixture runs a 2-of-3 Key Ceremony and seals a one-file tree.
func ceremonyFixture(t *testing.T) (manifest, bundle []byte, payloads []ceremony.SharePayload) {
	t.Helper()
	m, files, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "kbs-config.toml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := seal.Seal(&b, src, m.Recipient); err != nil {
		t.Fatal(err)
	}
	manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		payloads = append(payloads, ceremony.SharePayload{ShareFile: f})
	}
	return manifest, b.Bytes(), payloads
}

func newHelper(t *testing.T, manifest, bundle []byte, cdh helper.CDH) (*helper.Helper, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "trustee")
	h, err := helper.New(manifest, bundle, out, cdh)
	if err != nil {
		t.Fatal(err)
	}
	return h, out
}

func TestTwoSharesPublishTree(t *testing.T) {
	manifest, bundle, payloads := ceremonyFixture(t)
	h, out := newHelper(t, manifest, bundle, fakeCDH(t, payloads[0], payloads[2]))

	for i, want := range []bool{false, true} {
		published, err := h.CollectShare(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if published != want {
			t.Fatalf("CollectShare %d: published = %v, want %v", i+1, published, want)
		}
	}
	for _, name := range []string{"kbs-config.toml", helper.CompletionMarker} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("published tree: %v", err)
		}
	}
	if _, err := os.Stat(out + ".staging"); !os.IsNotExist(err) {
		t.Error("staging directory left behind")
	}
}

func TestOneShareStaysLocked(t *testing.T) {
	manifest, bundle, payloads := ceremonyFixture(t)
	h, out := newHelper(t, manifest, bundle, fakeCDH(t, payloads[1]))

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
	manifest, bundle, payloads := ceremonyFixture(t)
	h, out := newHelper(t, manifest, bundle, fakeCDH(t, payloads[0], payloads[0], payloads[2]))

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, bundle, payloads := ceremonyFixture(t)
			bad := payloads[0]
			tt.mutate(&bad)
			h, out := newHelper(t, manifest, bundle, fakeCDH(t, bad, payloads[1]))

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
	manifest, bundle, payloads := ceremonyFixture(t)
	bad := payloads[1]
	bad.Index = 7
	h, _ := newHelper(t, manifest, bundle, fakeCDH(t, bad, bad))
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
	if _, err := helper.New(manifest, nil, t.TempDir(), fakeCDH(t)); err == nil {
		t.Fatal("New accepted threshold 3 with 2 shares")
	}
}

func TestCDHErrorIsReturned(t *testing.T) {
	manifest, bundle, _ := ceremonyFixture(t)
	h, _ := newHelper(t, manifest, bundle, fakeCDH(t))
	if _, err := h.CollectShare(t.Context()); err == nil {
		t.Fatal("CollectShare succeeded when the CDH returned 404")
	}
}

func TestNewRejectsBadManifest(t *testing.T) {
	if _, err := helper.New([]byte("{"), nil, t.TempDir(), fakeCDH(t)); err == nil {
		t.Fatal("New accepted a malformed Ceremony Manifest")
	}
}
