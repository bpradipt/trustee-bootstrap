package cli_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// approve checks the Share against the Operator Policy before it contacts
// the Bootstrap Helper or starts the Operator Verifier: with no helper on
// the network, any later step would fail differently.
func TestApproveChecksShareBeforeAnythingStarts(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	alicePolicy := buildPolicy(t, f, "alice")
	var forged ceremony.ShareFile
	readJSON(t, filepath.Join(f.ceremonyDir, "alice.share"), &forged)
	forged.Share[0] ^= 1
	forgedFile := filepath.Join(t.TempDir(), "forged.share")
	b, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(forgedFile, b, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tt := range map[string]struct{ shareFile, want string }{
		"another holder's Share": {filepath.Join(f.ceremonyDir, "carol.share"), "index 3"},
		"forged Share":           {forgedFile, "Share Commitment"},
	} {
		ws := &workstation{t: t, cvm: &memnet.Network{}}
		_, err := ws.run("approve", "--endpoint", "http://"+helperAddr, "--policy", alicePolicy, "--share-file", tt.shareFile)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: approve = %v, want %q", name, err, tt.want)
		}
		if len(ws.started) != 0 {
			t.Errorf("%s: approve started the Operator Verifier", name)
		}
	}
}

func TestApproveServesSharePayload(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	var cvm memnet.Network
	startTrusteeCVM(t, f, &cvm, io.Discard)
	ws := &workstation{t: t, cvm: &cvm}

	_, err := ws.run("approve", "--endpoint", "http://"+helperAddr, "--policy", buildPolicy(t, f, "bob"),
		"--share-file", filepath.Join(f.ceremonyDir, "bob.share"), "--kbs-binary", "/opt/kbs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(ws.output, ""), "not a production Operator Policy") {
		t.Error("approve printed no warning for a policy with untested claim profiles")
	}
	if len(ws.started) != 1 || ws.started[0].KBSBinary != "/opt/kbs" {
		t.Fatalf("Operator Verifiers started: %+v, want one with --kbs-binary", ws.started)
	}
	var got ceremony.SharePayload
	if err := json.Unmarshal(ws.started[0].SharePayload, &got); err != nil {
		t.Fatal(err)
	}
	want := f.payloads[1]
	if got.Index != want.Index || got.KeyID != want.KeyID || string(got.Share) != string(want.Share) || got.BundleSHA256 != want.BundleSHA256 {
		t.Errorf("Share payload = index %d bundle %s, want bob's for %s", got.Index, got.BundleSHA256, want.BundleSHA256)
	}
}

// AT-18: SIGINT or SIGTERM ends approve through its normal cleanup, so the
// Operator Verifier stops. Without a handler the signal would kill the test.
func TestApproveStopsTheOperatorVerifierOnSignal(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	policyDir := buildPolicy(t, f, "alice")
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		var cvm memnet.Network
		startTrusteeCVM(t, f, &cvm, io.Discard)
		stopped := false
		start := func(ctx context.Context, _ string, _ verifier.Options) (string, func(), error) {
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			<-ctx.Done()
			return "127.0.0.1:1", func() { stopped = true }, nil
		}
		client := &http.Client{Transport: &http.Transport{DialContext: cvm.DialContext}}
		cmd := cli.NewTrusteeBootstrapCmdWith(client, (&memnet.Network{}).DialContext, start)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"approve", "--endpoint", "http://" + helperAddr, "--policy", policyDir,
			"--share-file", filepath.Join(f.ceremonyDir, "alice.share")})
		if err := cmd.Execute(); err == nil || !stopped {
			t.Errorf("%v: approve = %v, Operator Verifier stopped: %v; want an error and a stop", sig, err, stopped)
		}
	}
}

// The relay limits can be lowered, never disabled: approve refuses zero or
// negative limits before it starts anything.
func TestApproveRefusesDisabledRelayLimits(t *testing.T) {
	f := keyCeremonyAndSeal(t)
	policyDir := buildPolicy(t, f, "alice")
	for _, flag := range []string{"--relay-idle-timeout=0", "--relay-total-timeout=-1s", "--relay-idle-timeout=31s"} {
		ws := &workstation{t: t, cvm: &memnet.Network{}}
		_, err := ws.run("approve", "--endpoint", "http://"+helperAddr, "--policy", policyDir,
			"--share-file", filepath.Join(f.ceremonyDir, "alice.share"), flag)
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("%s: approve = %v, want a relay limit error", flag, err)
		}
		if len(ws.started) != 0 {
			t.Errorf("%s: approve started the Operator Verifier", flag)
		}
	}
}
