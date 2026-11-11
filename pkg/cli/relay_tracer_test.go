package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/internal/trusteetest"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

const (
	helperAddr   = "trustee-cvm:8080" // the Bootstrap Helper's Service
	proxyAddr    = "127.0.0.1:8081"   // the guest-loopback proxy: Init-Data's KBS URL
	kbsSharePath = "/kbs/v0/resource/trustee-bootstrap/share/current"
)

// startTrusteeCVM runs the Bootstrap Helper on cvm and returns its --out. Its
// fake CDH answers each get-resource call with a plain HTTP GET through the
// guest-loopback proxy, where the real CDH would run RCAR.
func startTrusteeCVM(t *testing.T, f unlockFixture, cvm *memnet.Network) string {
	t.Helper()
	kbs := &http.Client{Transport: &http.Transport{DialContext: cvm.DialContext, DisableKeepAlives: true}}
	cdh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+proxyAddr+kbsSharePath, nil)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := kbs.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			t.Error(err)
		}
	})
	out := f.out
	h, err := helper.New(f.manifest, sha256Hex(f.manifest), f.bundle, out, helper.CDH{URL: "http://127.0.0.1:8006", Client: &http.Client{Transport: serveInProcess{cdh}}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := cvm.Listen("tcp", helperAddr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h.Handler(func() (net.Listener, error) { return cvm.Listen("tcp", proxyAddr) }, relay.DefaultLimits())}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return out
}

// workstation is a Security Operator's machine: its own loopback network, a
// route to the Trustee CVM, and a stub Operator Verifier.
type workstation struct {
	t        *testing.T
	loopback memnet.Network
	cvm      *memnet.Network
	deny     bool               // the verifier's resource policy refuses release
	started  []verifier.Options // every Operator Verifier approve started
	output   []string           // everything the CLI printed
}

func (w *workstation) run(args ...string) (string, error) {
	w.t.Helper()
	var stdout, stderr bytes.Buffer
	client := &http.Client{Transport: &http.Transport{DialContext: w.cvm.DialContext}}
	cmd := cli.NewTrusteeBootstrapCmdWith(client, w.loopback.DialContext, w.startStubVerifier)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	w.output = append(w.output, stdout.String(), stderr.String())
	return stdout.String(), err
}

// startStubVerifier stands in for the Operator Verifier: it serves this
// operator's Share payload at the KBS resource path, with no attestation.
func (w *workstation) startStubVerifier(_ context.Context, address string, opts verifier.Options) (string, func(), error) {
	w.started = append(w.started, opts)
	if host, _, err := net.SplitHostPort(address); err != nil || host != "127.0.0.1" {
		w.t.Errorf("Operator Verifier listens on %q, want 127.0.0.1 only", address)
	}
	if !strings.Contains(opts.ResourcePolicy, "affirming") || len(opts.ReferenceValues[policy.RefTrustedAKs]) == 0 {
		w.t.Errorf("Operator Verifier started without the Operator Policy: %+v", opts)
	}
	l, err := w.loopback.Listen("tcp", address)
	if err != nil {
		return "", nil, err
	}
	payload := opts.SharePayload
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != kbsSharePath {
			http.NotFound(rw, r)
			return
		}
		if w.deny {
			http.Error(rw, "policy denied", http.StatusUnauthorized)
			return
		}
		if _, err := rw.Write(payload); err != nil {
			w.t.Error(err)
		}
	})}
	go srv.Serve(l)
	return l.Addr().String(), func() { srv.Close() }, nil
}

func (w *workstation) status(endpoint string) helper.Status {
	w.t.Helper()
	out, err := w.run("status", "--endpoint", endpoint)
	if err != nil {
		w.t.Fatalf("status: %v", err)
	}
	var st helper.Status
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		w.t.Fatalf("status printed %q: %v", out, err)
	}
	return st
}

func (w *workstation) assertStatus(endpoint string, state helper.State, accepted []int) helper.Status {
	w.t.Helper()
	st := w.status(endpoint)
	if st.State != state || !slices.Equal(st.Accepted, accepted) {
		w.t.Errorf("status = %s %v, want %s %v", st.State, st.Accepted, state, accepted)
	}
	return st
}

func (w *workstation) approve(endpoint string, f unlockFixture, holder string) (string, error) {
	w.t.Helper()
	return w.run("approve", "--endpoint", endpoint, "--policy", buildPolicy(w.t, f, holder),
		"--share-file", filepath.Join(f.ceremonyDir, holder+".share"))
}

// buildPolicy runs holder's `policy build` for a tpm Trustee CVM and returns
// the Operator Policy directory.
func buildPolicy(t *testing.T, f unlockFixture, holder string) string {
	t.Helper()
	dir := t.TempDir()
	initData := filepath.Join(dir, "init.toml")
	rv := filepath.Join(dir, "rv.json")
	if err := os.WriteFile(initData, []byte("version = \"0.1.0\"\nalgorithm = \"sha256\"\n[data]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rv, []byte(`{"trusted_aks":["AK"],"tpm_pcr11":["00"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "policy")
	printed := mustRun(t, "policy", "build", "--init-data", initData, "--reference-values", rv, "--accept-tee", "tpm", "--allow-untested-profiles",
		"--bundle-sha256", f.payloads[0].BundleSHA256, "--manifest", filepath.Join(f.ceremonyDir, cli.ManifestFile),
		"--share-file", filepath.Join(f.ceremonyDir, holder+".share"), "--out-dir", out)
	toml, err := os.ReadFile(initData)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(toml); printed != "init_data_sha256 "+hex.EncodeToString(sum[:])+"\n" {
		t.Errorf("policy build printed %q, want the Init-Data digest", printed)
	}
	return out
}

// AT-13 through the relay, in-process.
func TestTwoOperatorsUnlockThroughRelay(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	var cvm memnet.Network
	out := startTrusteeCVM(t, f, &cvm)
	ws := &workstation{t: t, cvm: &cvm}
	endpoint := "http://" + helperAddr

	first := ws.assertStatus(endpoint, helper.StateCollecting, []int{})
	if first.BootID == "" || first.Threshold != 2 {
		t.Errorf("status = %+v, want a boot_id and threshold 2", first)
	}
	if got, err := ws.approve(endpoint, f, "alice"); err != nil || got != "accepted\n" {
		t.Fatalf("alice's approve = %q, %v; want accepted", got, err)
	}
	ws.assertStatus(endpoint, helper.StateCollecting, []int{1})
	if _, err := ws.approve(endpoint, f, "alice"); err == nil || !strings.Contains(err.Error(), "already accepted") {
		t.Errorf("alice's second approve: err = %v, want already accepted", err)
	}
	if got, err := ws.approve(endpoint, f, "carol"); err != nil || got != "accepted\n" {
		t.Fatalf("carol's approve = %q, %v; want accepted", got, err)
	}
	last := ws.assertStatus(endpoint, helper.StatePublished, []int{1, 3})
	if last.BootID != first.BootID {
		t.Errorf("boot_id changed from %s to %s", first.BootID, last.BootID)
	}

	got, err := os.ReadFile(filepath.Join(out, verifier.ResourcePolicyPath))
	if err != nil || string(got) != trusteetest.ResourcePolicy {
		t.Fatalf("published resource.rego = %q, %v", got, err)
	}
	assertNoShareBytes(t, ws.output, f.payloads)
}

func assertNoShareBytes(t *testing.T, output []string, payloads []ceremony.SharePayload) {
	t.Helper()
	all := strings.Join(output, "\n")
	for _, p := range payloads {
		if strings.Contains(all, string(p.Share)) || strings.Contains(all, base64.StdEncoding.EncodeToString(p.Share)) {
			t.Errorf("the CLI printed index %d's Share", p.Index)
		}
	}
}

// When no Share reaches the helper, approve reports a sanitized error, not
// "accepted", and the helper counts nothing.
func TestApproveReportsShareNotAccepted(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	var cvm memnet.Network
	startTrusteeCVM(t, f, &cvm)
	ws := &workstation{t: t, cvm: &cvm, deny: true}
	endpoint := "http://" + helperAddr

	got, err := ws.approve(endpoint, f, "bob")
	if err == nil || got != "" {
		t.Fatalf("approve = %q, %v; want an error", got, err)
	}
	if !strings.Contains(err.Error(), "not accepted") {
		t.Errorf("approve error = %v, want it to say the Share was not accepted", err)
	}
	ws.assertStatus(endpoint, helper.StateCollecting, []int{})
	assertNoShareBytes(t, ws.output, f.payloads)
}
