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

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(m *ceremony.Manifest)
		wantErr string
	}{
		{name: "split output", mutate: func(*ceremony.Manifest) {}},
		{name: "threshold equals shares", mutate: func(m *ceremony.Manifest) { m.Threshold = 3 }},
		{name: "threshold 1", mutate: func(m *ceremony.Manifest) { m.Threshold = 1 }, wantErr: "threshold 1 is below 2"},
		{name: "threshold above shares", mutate: func(m *ceremony.Manifest) { m.Threshold = 4 }, wantErr: "threshold 4 is above the 3 shares"},
		{
			name:    "repeated index",
			mutate:  func(m *ceremony.Manifest) { m.Shares[2].Index = 1 },
			wantErr: "share index 1 repeats",
		},
		{
			name:    "repeated commitment",
			mutate:  func(m *ceremony.Manifest) { m.Shares[2].Commitment = m.Shares[0].Commitment },
			wantErr: "the Share Commitment of index 3 repeats",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(&m)
			err = m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("Validate = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestManifestCommitmentFor(t *testing.T) {
	m, _, err := ceremony.Split(2, []string{"alice", "bob", "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.CommitmentFor(2); err != nil || got != m.Shares[1].Commitment {
		t.Errorf("CommitmentFor(2) = %q, %v; want %q", got, err, m.Shares[1].Commitment)
	}
	if _, err := m.CommitmentFor(4); err == nil {
		t.Error("CommitmentFor accepted index 4 of 3")
	}
}

func TestCommitment(t *testing.T) {
	const want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := ceremony.Commitment([]byte("hello")); got != want {
		t.Errorf("Commitment = %q, want %q", got, want)
	}
}
