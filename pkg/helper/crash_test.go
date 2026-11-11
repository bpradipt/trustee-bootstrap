package helper_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// crashed is what a crash hook panics with. Nothing after the hook runs, as
// if the helper's process died there.
const crashed = "crashed"

// crashAtRename gives h its two Shares and returns what the helper panicked
// with on the way to publication.
func crashAtRename(t *testing.T, h *helper.Helper) (crash any) {
	t.Helper()
	defer func() { crash = recover() }()
	for range 2 {
		if _, err := h.CollectShare(t.Context()); err != nil {
			t.Error(err)
		}
	}
	return nil
}

func assertGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %v, want it gone", p, err)
		}
	}
}

// AT-15, AT-26: the helper crashes just before the rename, with the marked
// tree staged. On restart it wipes staging and starts a new boot with no
// Shares, so only a new Unlock Ceremony publishes the tree.
func TestCrashBeforeRenameNeedsNewCeremony(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	helper.SetRename(t, func(string, string) error { panic(crashed) })
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	if got := crashAtRename(t, h); got != crashed {
		t.Fatalf("the helper did not crash at the rename: %v", got)
	}
	if _, err := os.Stat(filepath.Join(out+".staging", helper.CompletionMarker)); err != nil {
		t.Fatalf("no marked staging tree at the crash: %v", err)
	}

	helper.SetRename(t, os.Rename)
	published, err := helper.Recover(out)
	if err != nil || published {
		t.Fatalf("Recover = %v, %v; want a fresh start", published, err)
	}
	assertGone(t, out, out+".staging")
	again := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[2]))
	s := again.Status()
	if s.BootID == h.Status().BootID || len(s.Accepted) != 0 || s.State != helper.StateCollecting {
		t.Fatalf("status after the restart = %+v, want a new boot_id and no Shares", s)
	}
	for i, want := range []bool{false, true} {
		published, err := again.CollectShare(t.Context())
		if err != nil || published != want {
			t.Fatalf("new ceremony, Share %d: published = %v, %v; want %v", i+1, published, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(out, helper.CompletionMarker)); err != nil {
		t.Errorf("the new ceremony published no tree: %v", err)
	}
}

// AT-26: the helper crashes just after the rename. On restart the completion
// marker shows the tree is published, so no new ceremony is needed.
func TestCrashAfterRenameKeepsPublishedTree(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	helper.SetRename(t, func(oldpath, newpath string) error {
		if err := os.Rename(oldpath, newpath); err != nil {
			return err
		}
		panic(crashed)
	})
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	if got := crashAtRename(t, h); got != crashed {
		t.Fatalf("the helper did not crash after the rename: %v", got)
	}

	published, err := helper.Recover(out)
	if err != nil || !published {
		t.Fatalf("Recover = %v, %v; want the published tree found", published, err)
	}
	for _, name := range []string{verifier.ConfigFile, verifier.ResourcePolicyPath, helper.CompletionMarker} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("published tree after the restart: %v", err)
		}
	}
}

// A failed rename fails the unlock and leaves no staging behind.
func TestFailedRenamePublishesNothing(t *testing.T) {
	manifest, bundle, payloads, out := ceremonyFixture(t)
	helper.SetRename(t, func(string, string) error { return errors.New("rename refused") })
	h := newHelper(t, manifest, bundle, out, fakeCDH(t, payloads[0], payloads[1]))
	if _, err := h.CollectShare(t.Context()); err != nil {
		t.Fatal(err)
	}
	if published, err := h.CollectShare(t.Context()); published || err == nil {
		t.Fatalf("CollectShare = %v, %v; want the rename's failure", published, err)
	}
	assertGone(t, out, out+".staging")
}

func TestRecoverFailsWhenOutIsUnreadable(t *testing.T) {
	out := filepath.Join(t.TempDir(), "trustee")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if published, err := helper.Recover(out); published || err == nil {
		t.Fatalf("Recover = %v, %v; want an error for a file at --out", published, err)
	}
}
