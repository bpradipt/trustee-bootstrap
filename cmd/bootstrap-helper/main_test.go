package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// mounts is a Key Ceremony's files as the host mounts them.
type mounts struct {
	manifest, bundle string // paths
	manifestSHA256   string
	recipient        string
	payloads         []ceremony.SharePayload
	out              string // where the sealed tree expects to be published
}

// fixture runs a 2-of-2 Key Ceremony, seals a Trustee config tree whose
// bundle-name file holds "approved" and writes the manifest and the bundle.
func fixture(t *testing.T) mounts {
	t.Helper()
	m, files, err := ceremony.Split(2, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := mounts{
		manifest:       filepath.Join(dir, "ceremony.json"),
		bundle:         filepath.Join(dir, "bundle.age"),
		manifestSHA256: sha256Hex(mb),
		recipient:      m.Recipient,
		out:            filepath.Join(t.TempDir(), "trustee"),
	}
	bundle := sealTree(t, m.Recipient, f.out, "approved")
	for _, s := range files {
		f.payloads = append(f.payloads, ceremony.SharePayload{ShareFile: s, BundleSHA256: sha256Hex(bundle)})
	}
	writeFile(t, f.manifest, mb)
	writeFile(t, f.bundle, bundle)
	return f
}

func sealTree(t *testing.T, recipient, out, name string) []byte {
	t.Helper()
	tree := trusteetest.Tree(t, out)
	writeFile(t, filepath.Join(tree, "bundle-name"), []byte(name))
	var b bytes.Buffer
	if err := seal.Seal(&b, tree, recipient); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

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

// fakeCDH serves one Share payload per get-resource call, in order.
func fakeCDH(t *testing.T, payloads ...ceremony.SharePayload) *http.Client {
	t.Helper()
	cdh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != helper.ShareResourcePath || len(payloads) == 0 {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(payloads[0]); err != nil {
			t.Error(err)
		}
		payloads = payloads[1:]
	})
	return &http.Client{Transport: serveInProcess{cdh}}
}

// openRelay opens a relay to the helper at helper:8090 and returns the code
// the helper closed it with. The previous relay may still be closing, so a
// 409 means try again.
func openRelay(t *testing.T, n *memnet.Network) websocket.StatusCode {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DialContext: n.DialContext}}
	for {
		ws, resp, err := websocket.Dial(t.Context(), "http://helper:8090"+helper.RelayPath, &websocket.DialOptions{HTTPClient: client})
		if resp != nil && resp.StatusCode == http.StatusConflict {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ws.Read(t.Context())
		return websocket.CloseStatus(err)
	}
}

func TestRunFailsWithExitOne(t *testing.T) {
	f := fixture(t)
	out := filepath.Join(t.TempDir(), "trustee")
	refuse := func(string, string) (net.Listener, error) { return nil, errors.New("listen refused") }
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--no-such-flag"}},
		{"missing manifest", []string{"--manifest", f.manifest + ".gone", "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", out}},
		{"missing bundle", []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle + ".gone", "--out", out}},
		// AT-11
		{"--manifest-sha256 dropped", []string{"--manifest", f.manifest, "--bundle", f.bundle, "--out", out}},
		{"swapped manifest", []string{"--manifest", f.manifest, "--manifest-sha256", sha256Hex([]byte("{}")), "--bundle", f.bundle, "--out", out}},
		{"listen refused", []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", out}},
		{"--out missing", []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle}},
		{"--out is a file", []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", f.bundle}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code := run(tt.args, refuse, fakeCDH(t)); code != 1 {
				t.Errorf("run exited %d, want 1", code)
			}
		})
	}
}

// With a listener that dies at once, the helper gets as far as serving the
// Helper API on --listen, then fails.
func TestRunServesOnListenAddress(t *testing.T) {
	f := fixture(t)
	var n memnet.Network
	var listened []string
	dead := func(network, address string) (net.Listener, error) {
		listened = append(listened, address)
		l, err := n.Listen(network, address)
		if err != nil {
			return nil, err
		}
		return l, l.Close()
	}
	args := []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", t.TempDir(), "--listen", ":9443"}
	if code := run(args, dead, fakeCDH(t)); code != 1 {
		t.Errorf("run exited %d, want 1", code)
	}
	if len(listened) != 1 || listened[0] != ":9443" {
		t.Errorf("listened on %v, want [:9443]", listened)
	}
}

// The relay limits can be lowered, never disabled: the helper refuses zero or
// negative limits before it listens.
func TestRunRefusesDisabledRelayLimits(t *testing.T) {
	f := fixture(t)
	for _, flag := range []string{"--relay-idle-timeout=0", "--relay-total-timeout=-1s", "--relay-total-timeout=121s"} {
		var listened []string
		listen := func(_, address string) (net.Listener, error) {
			listened = append(listened, address)
			return nil, errors.New("listen refused")
		}
		args := []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", t.TempDir(), flag}
		if code := run(args, listen, fakeCDH(t)); code != 1 || len(listened) != 0 {
			t.Errorf("%s: run exited %d after listening on %v, want 1 before listening", flag, code, listened)
		}
	}
}

func TestRunFailsAtDeadline(t *testing.T) {
	f := fixture(t)
	var n memnet.Network
	args := []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", t.TempDir(), "--deadline", "1ms"}
	if code := run(args, n.Listen, fakeCDH(t)); code != 1 {
		t.Errorf("run exited %d, want 1", code)
	}
}

// AT-23: the host swaps both mounted files after LOCKED. The helper still
// unseals the bundle it read in LOCKED, and the approved Shares unlock it.
func TestRunUnsealsTheBundleReadInLocked(t *testing.T) {
	f := fixture(t)
	var n memnet.Network
	locked := make(chan struct{})
	listen := func(network, address string) (net.Listener, error) {
		l, err := n.Listen(network, address)
		if address == "helper:8090" {
			close(locked) // the files are read before the Helper API listens
		}
		return l, err
	}
	out := f.out
	args := []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", out, "--listen", "helper:8090"}
	code := make(chan int, 1)
	go func() { code <- run(args, listen, fakeCDH(t, f.payloads...)) }()

	<-locked
	writeFile(t, f.bundle, sealTree(t, f.recipient, out, "host"))
	writeFile(t, f.manifest, []byte("{}"))
	for range f.payloads {
		if got := openRelay(t, &n); got != websocket.StatusNormalClosure {
			t.Fatalf("relay closed with %v, want the Share accepted", got)
		}
	}
	if c := <-code; c != 0 {
		t.Fatalf("run exited %d, want 0", c)
	}
	got, err := os.ReadFile(filepath.Join(out, "bundle-name"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "approved" {
		t.Errorf("published bundle-name = %q, want the approved bundle's", got)
	}
}

// AT-26: restarted after the rename, the helper finds the marked tree and
// exits 0 at once, without reading the mounts or serving a ceremony.
func TestRunExitsZeroWhenAlreadyPublished(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trustee")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(out, helper.CompletionMarker), nil)
	listen := func(string, string) (net.Listener, error) {
		t.Error("the helper listened with the tree already published")
		return nil, errors.New("no listening")
	}
	args := []string{"--manifest", "/gone/ceremony.json", "--bundle", "/gone/bundle.age", "--out", out}
	if code := run(args, listen, fakeCDH(t)); code != 0 {
		t.Errorf("run exited %d, want 0", code)
	}
}

// AT-15: restarted before the rename, the helper wipes the staging tree the
// crash left behind and starts over.
func TestRunWipesLeftoverStaging(t *testing.T) {
	f := fixture(t)
	staging := f.out + ".staging"
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(staging, helper.CompletionMarker), nil)
	refuse := func(string, string) (net.Listener, error) {
		if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("staging at LOCKED: %v, want it gone", err)
		}
		return nil, errors.New("listen refused")
	}
	args := []string{"--manifest", f.manifest, "--manifest-sha256", f.manifestSHA256, "--bundle", f.bundle, "--out", f.out}
	if code := run(args, refuse, fakeCDH(t)); code != 1 {
		t.Errorf("run exited %d, want 1", code)
	}
}

func TestReadCappedAcceptsTheCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.age")
	writeFile(t, path, make([]byte, maxFileSize))
	b, err := readCapped(path)
	if err != nil || len(b) != maxFileSize {
		t.Fatalf("readCapped = %d bytes, %v; want %d bytes", len(b), err, maxFileSize)
	}
}

func TestReadCappedRefusesMore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.age")
	writeFile(t, path, make([]byte, maxFileSize+1))
	if _, err := readCapped(path); err == nil {
		t.Fatal("readCapped read a file over the size cap")
	}
}
