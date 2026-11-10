package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
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
	startTrusteeCVM(t, f, &cvm)
	ws := &workstation{t: t, cvm: &cvm}

	_, err := ws.run("approve", "--endpoint", "http://"+helperAddr, "--policy", buildPolicy(t, f, "bob"),
		"--share-file", filepath.Join(f.ceremonyDir, "bob.share"), "--kbs-binary", "/opt/kbs")
	if err != nil {
		t.Fatal(err)
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
