// Package helper is the Bootstrap Helper: it collects Shares from the CDH,
// reconstructs the bootstrap identity and publishes the unsealed tree.
package helper

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// ShareResourcePath is the CDH get-resource path for the Share payload.
const ShareResourcePath = "/cdh/resource/trustee-bootstrap/share/current"

// CompletionMarker is written into the published tree; its presence proves
// publication finished.
const CompletionMarker = ".trustee-bootstrap-published"

// CDH is the sandbox's Confidential Data Hub get-resource API. In a Trustee
// CVM, URL is http://127.0.0.1:8006 and Client is http.DefaultClient.
type CDH struct {
	URL    string
	Client *http.Client
}

// SharePayload asks the CDH for the Share payload resource.
func (c CDH) SharePayload(ctx context.Context) (ceremony.SharePayload, error) {
	var p ceremony.SharePayload
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+ShareResourcePath, nil)
	if err != nil {
		return p, fmt.Errorf("build CDH request: %w", err)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return p, fmt.Errorf("get Share payload from CDH: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return p, fmt.Errorf("get Share payload from CDH: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return p, fmt.Errorf("read Share payload: %w", err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("parse Share payload: %w", err)
	}
	return p, nil
}

// State is the Bootstrap Helper's place in its state machine (spec §5).
type State string

// States a status request can observe.
const (
	StateCollecting State = "COLLECTING"
	StatePublished  State = "PUBLISHED"
	StateFailed     State = "FAILED"
)

// Status is the body of GET /bootstrap/v1/status. It holds no secrets.
type Status struct {
	BootID    string `json:"boot_id"`
	KeyID     string `json:"key_id"`
	State     State  `json:"state"`
	Threshold int    `json:"threshold"`
	Accepted  []int  `json:"accepted"`
	Rejected  []int  `json:"rejected"`
}

// Helper is one boot's Bootstrap Helper.
type Helper struct {
	manifest ceremony.Manifest
	bundle   []byte
	out      string
	cdh      CDH
	bootID   string
	relayMu  sync.Mutex    // held by the one open relay
	done     chan struct{} // closed on leaving COLLECTING

	mu       sync.Mutex // guards the fields below
	state    State
	shares   [][]byte
	accepted []int
	rejected []int
}

// New returns a Helper for the Ceremony Manifest and Sealed Bundle bytes.
// It asks cdh for Share payloads and publishes the unsealed tree into out.
func New(manifest, bundle []byte, out string, cdh CDH) (*Helper, error) {
	h := &Helper{
		bundle:   bundle,
		out:      out,
		cdh:      cdh,
		bootID:   rand.Text(),
		done:     make(chan struct{}),
		state:    StateCollecting,
		accepted: []int{},
		rejected: []int{},
	}
	if err := json.Unmarshal(manifest, &h.manifest); err != nil {
		return nil, fmt.Errorf("parse ceremony manifest: %w", err)
	}
	if err := h.manifest.Validate(); err != nil {
		return nil, fmt.Errorf("ceremony manifest: %w", err)
	}
	return h, nil
}

// Status reports the helper's progress.
func (h *Helper) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return Status{
		BootID:    h.bootID,
		KeyID:     h.manifest.KeyID,
		State:     h.state,
		Threshold: h.manifest.Threshold,
		Accepted:  slices.Clone(h.accepted),
		Rejected:  slices.Clone(h.rejected),
	}
}

// CollectShare fetches one Share payload from the CDH and counts it if it
// passes the COLLECTING checks. A rejected payload is not counted, and its
// index is reported in status and in the returned error. Once threshold
// Shares are in, it unseals and publishes the tree and returns true.
func (h *Helper) CollectShare(ctx context.Context) (bool, error) {
	p, err := h.cdh.SharePayload(ctx)
	if err != nil {
		return false, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != StateCollecting {
		return false, fmt.Errorf("unlock already ended: %s", h.state)
	}
	if err := h.check(p); err != nil {
		if !slices.Contains(h.rejected, p.Index) {
			h.rejected = append(h.rejected, p.Index)
		}
		return false, fmt.Errorf("reject Share index %d: %w", p.Index, err)
	}
	h.shares = append(h.shares, p.Share)
	h.accepted = append(h.accepted, p.Index)
	if len(h.shares) < h.manifest.Threshold {
		return false, nil
	}
	err = h.publish()
	h.state = StatePublished
	if err != nil {
		h.state = StateFailed
	}
	close(h.done)
	return err == nil, err
}

// check applies the COLLECTING checks (spec §5) to a Share payload.
func (h *Helper) check(p ceremony.SharePayload) error {
	if p.KeyID != h.manifest.KeyID {
		return fmt.Errorf("key_id %q does not match the Ceremony Manifest", p.KeyID)
	}
	commitment, err := h.manifest.CommitmentFor(p.Index)
	if err != nil {
		return err
	}
	if slices.Contains(h.accepted, p.Index) {
		return errors.New("index already accepted")
	}
	if ceremony.Commitment(p.Share) != commitment {
		return errors.New("the Share does not match its Share Commitment")
	}
	return nil
}

// publish unseals into a staging directory beside out, marks it complete,
// then renames it into place.
func (h *Helper) publish() error {
	id, err := ceremony.Combine(h.shares)
	for _, s := range h.shares {
		clear(s)
	}
	if err != nil {
		return err
	}
	staging := h.out + ".staging"
	if err := seal.Unseal(h.bundle, id, staging); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staging, CompletionMarker), nil, 0o600); err != nil {
		return fmt.Errorf("write completion marker: %w", err)
	}
	if err := os.Rename(staging, h.out); err != nil {
		return fmt.Errorf("publish tree: %w", err)
	}
	return nil
}
