package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/internal/memnet"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// fixture writes a Ceremony Manifest and Sealed Bundle and returns their paths.
func fixture(t *testing.T) (manifest, bundle string) {
	t.Helper()
	m, _, err := ceremony.Split(2, []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "kbs-config.toml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := seal.Seal(&b, tree, m.Recipient); err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	manifest, bundle = filepath.Join(dir, "ceremony.json"), filepath.Join(dir, "bundle.age")
	for path, data := range map[string][]byte{manifest: mb, bundle: b.Bytes()} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return manifest, bundle
}

func TestRunFailsWithExitOne(t *testing.T) {
	manifest, bundle := fixture(t)
	out := filepath.Join(t.TempDir(), "trustee")
	refuse := func(string, string) (net.Listener, error) { return nil, errors.New("listen refused") }
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--no-such-flag"}},
		{"missing manifest", []string{"--manifest", manifest + ".gone", "--bundle", bundle, "--out", out}},
		{"missing bundle", []string{"--manifest", manifest, "--bundle", bundle + ".gone", "--out", out}},
		{"malformed manifest", []string{"--manifest", bundle, "--bundle", bundle, "--out", out}},
		{"listen refused", []string{"--manifest", manifest, "--bundle", bundle, "--out", out}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code := run(tt.args, refuse); code != 1 {
				t.Errorf("run exited %d, want 1", code)
			}
		})
	}
}

// With a listener that dies at once, the helper gets as far as serving the
// Helper API on --listen, then fails.
func TestRunServesOnListenAddress(t *testing.T) {
	manifest, bundle := fixture(t)
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
	args := []string{"--manifest", manifest, "--bundle", bundle, "--out", t.TempDir(), "--listen", ":9443"}
	if code := run(args, dead); code != 1 {
		t.Errorf("run exited %d, want 1", code)
	}
	if len(listened) != 1 || listened[0] != ":9443" {
		t.Errorf("listened on %v, want [:9443]", listened)
	}
}
