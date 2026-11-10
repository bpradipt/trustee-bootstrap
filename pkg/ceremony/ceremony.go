// Package ceremony owns the Key Ceremony formats: the Ceremony Manifest,
// Share files, Share payloads, and splitting and combining the bootstrap key.
package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"filippo.io/age"
	"github.com/hashicorp/vault/shamir"
)

// Version is the format version of every artifact in this package.
const Version = 1

// Manifest is the Ceremony Manifest (ceremony.json).
type Manifest struct {
	Version   int             `json:"version"`
	KeyID     string          `json:"key_id"`
	Threshold int             `json:"threshold"`
	Recipient string          `json:"recipient"`
	Shares    []ManifestShare `json:"shares"`
}

// ManifestShare records one share index, its holder label and its Share Commitment.
type ManifestShare struct {
	Index      int    `json:"index"`
	Holder     string `json:"holder"`
	Commitment string `json:"commitment"`
}

// ShareFile is the file a Security Operator holds. Share is the raw Vault
// Shamir part; encoding/json writes it as base64.
type ShareFile struct {
	Version int    `json:"version"`
	KeyID   string `json:"key_id"`
	Index   int    `json:"index"`
	Share   []byte `json:"share"`
}

// SharePayload is the plaintext of the KBS resource an Operator Verifier
// serves: the Share file plus the Approved Bundle digest.
type SharePayload struct {
	ShareFile
	BundleSHA256 string `json:"bundle_sha256"`
}

// Commitment returns the Share Commitment of a Share.
func Commitment(share []byte) string {
	sum := sha256.Sum256(share)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Split generates a bootstrap key pair and splits its identity into one
// Share per holder, threshold of which recover it. The identity never leaves
// memory.
func Split(threshold int, holders []string) (Manifest, []ShareFile, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("generate identity: %w", err)
	}
	secret := []byte(id.String())
	defer clear(secret)
	parts, err := shamir.Split(secret, len(holders), threshold)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("split identity: %w", err)
	}
	recipient := id.Recipient().String()
	keyID := sha256.Sum256([]byte(recipient))
	m := Manifest{
		Version:   Version,
		KeyID:     hex.EncodeToString(keyID[:16]),
		Threshold: threshold,
		Recipient: recipient,
	}
	files := make([]ShareFile, len(parts))
	for i, part := range parts {
		index := i + 1
		m.Shares = append(m.Shares, ManifestShare{Index: index, Holder: holders[i], Commitment: Commitment(part)})
		files[i] = ShareFile{Version: Version, KeyID: m.KeyID, Index: index, Share: part}
	}
	return m, files, nil
}

// Combine recovers the bootstrap identity from threshold Shares.
func Combine(shares [][]byte) (*age.X25519Identity, error) {
	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("combine shares: %w", err)
	}
	defer clear(secret)
	id, err := age.ParseX25519Identity(string(secret))
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	return id, nil
}
