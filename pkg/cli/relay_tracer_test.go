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
	"sync"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
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

// startTrusteeCVM runs the Bootstrap Helper on cvm, with its audit records
// going to auditLog, and returns its --out. Its fake CDH answers each
// get-resource call with a plain HTTP GET through the guest-loopback proxy,
// where the real CDH would run RCAR.
func startTrusteeCVM(t *testing.T, f unlockFixture, cvm *memnet.Network, auditLog io.Writer) string {
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
	h, err := helper.New(f.manifest, sha256Hex(f.manifest), f.bundle, out, helper.CDH{URL: "http://127.0.0.1:8006", Client: &http.Client{Transport: serveInProcess{cdh}}}, audit.New(auditLog))
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
	out := startTrusteeCVM(t, f, &cvm, io.Discard)
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

// assertNoShareBytes fails if any Share appears in output raw, in hex, or in
// base64 or base64url with or without padding. The unpadded forms are
// prefixes of the padded ones, so they cover both.
func assertNoShareBytes(t *testing.T, output []string, payloads []ceremony.SharePayload) {
	t.Helper()
	all := strings.Join(output, "\n")
	for _, p := range payloads {
		for _, form := range []string{
			string(p.Share),
			hex.EncodeToString(p.Share),
			base64.RawStdEncoding.EncodeToString(p.Share),
			base64.RawURLEncoding.EncodeToString(p.Share),
		} {
			if strings.Contains(all, form) {
				t.Errorf("index %d's Share is in the output", p.Index)
			}
		}
	}
}

// syncBuffer is a bytes.Buffer that the helper's goroutines may write while
// the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A whole Unlock Ceremony, with one Share rejected, leaves audit records on
// both sides, and no Share in them.
func TestAuditRecordsCarryNoShare(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	var cvm memnet.Network
	var helperAudit syncBuffer
	startTrusteeCVM(t, f, &cvm, &helperAudit)
	ws := &workstation{t: t, cvm: &cvm}
	endpoint := "http://" + helperAddr

	// bob's Operator Policy names another bundle: his Share is released,
	// and the helper rejects it.
	other := f
	other.payloads = slices.Clone(f.payloads)
	other.payloads[0].BundleSHA256 = strings.Repeat("0", 64)
	if _, err := ws.approve(endpoint, other, "bob"); err == nil {
		t.Fatal("bob's approve for another bundle succeeded")
	}
	for _, holder := range []string{"alice", "carol"} {
		if _, err := ws.approve(endpoint, f, holder); err != nil {
			t.Fatalf("%s's approve: %v", holder, err)
		}
	}
	ws.assertStatus(endpoint, helper.StatePublished, []int{1, 3})

	helperLog, cliLog := helperAudit.String(), strings.Join(ws.output, "")
	for _, want := range []string{
		`"msg":"state_changed","boot_id":`, `"state":"COLLECTING"`, `"state":"PUBLISHED"`,
		`"msg":"relay_opened"`, `"msg":"relay_closed"`, `"reason":"accepted"`,
		`"msg":"share_rejected","boot_id":`, `"index":2,"reason":"bundle_sha256`,
		`"msg":"share_accepted","boot_id":`, `"index":3,"accepted":2`,
	} {
		if !strings.Contains(helperLog, want) {
			t.Errorf("helper audit lacks %s:\n%s", want, helperLog)
		}
	}
	for _, want := range []string{
		`"msg":"verifier_started","index":2`, `"msg":"verifier_stopped"`, `"msg":"relay_opened"`,
		`"msg":"relay_closed","index":1`, `"code":1000}`, `"code":1008,"error":"failed to get reader`,
		`"msg":"approve_result","index":2,"key_id":"` + f.payloads[1].KeyID, `"accepted":false,"error":"relay ended`,
		`"msg":"approve_result","index":3`, `"accepted":true}`,
	} {
		if !strings.Contains(cliLog, want) {
			t.Errorf("CLI audit lacks %s:\n%s", want, cliLog)
		}
	}
	assertNoShareBytes(t, []string{helperLog, cliLog}, f.payloads)
}

// When no Share reaches the helper, approve reports a sanitized error, not
// "accepted", and the helper counts nothing.
func TestApproveReportsShareNotAccepted(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	var cvm memnet.Network
	startTrusteeCVM(t, f, &cvm, io.Discard)
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
