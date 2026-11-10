package ceremony_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
)

func TestSplitThenCombineRecoversIdentity(t *testing.T) {
	m, files, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 || m.Threshold != 2 || len(m.Shares) != 3 || len(files) != 3 {
		t.Fatalf("unexpected manifest %+v with %d share files", m, len(files))
	}
	wantKeyID := sha256.Sum256([]byte(m.Recipient))
	if m.KeyID != hex.EncodeToString(wantKeyID[:16]) {
		t.Errorf("key_id %q is not derived from the recipient", m.KeyID)
	}
	for i, f := range files {
		s := m.Shares[i]
		if s.Index != i+1 || f.Index != i+1 || f.KeyID != m.KeyID || f.Version != 1 {
			t.Errorf("share %d: manifest %+v, file index %d key_id %q", i, s, f.Index, f.KeyID)
		}
		if s.Commitment != ceremony.Commitment(f.Share) {
			t.Errorf("share %d: commitment does not match its Share", i)
		}
	}
	if m.Shares[1].Holder != "bob" {
		t.Errorf("holder = %q, want bob", m.Shares[1].Holder)
	}

	id, err := ceremony.Combine([][]byte{files[2].Share, files[0].Share})
	if err != nil {
		t.Fatal(err)
	}
	if id.Recipient().String() != m.Recipient {
		t.Error("combined identity does not match the manifest recipient")
	}
}

func TestSplitRejectsThresholdAboveHolders(t *testing.T) {
	if _, _, err := ceremony.Split(3, []string{"alice", "bob"}); err == nil {
		t.Fatal("Split accepted threshold 3 with 2 holders")
	}
}

func TestCombineRejectsOneShare(t *testing.T) {
	_, files, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ceremony.Combine([][]byte{files[0].Share}); err == nil {
		t.Fatal("Combine accepted a single Share")
	}
}

func TestCommitment(t *testing.T) {
	const want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := ceremony.Commitment([]byte("hello")); got != want {
		t.Errorf("Commitment = %q, want %q", got, want)
	}
}
