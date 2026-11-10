// Package helper is the Bootstrap Helper: it collects Shares from the CDH,
// reconstructs the bootstrap identity and publishes the unsealed tree.
package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

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

// Helper is one boot's Bootstrap Helper.
type Helper struct {
	manifest ceremony.Manifest
	bundle   []byte
	out      string
	cdh      CDH
	shares   [][]byte
}

// New returns a Helper for the Ceremony Manifest and Sealed Bundle bytes.
// It asks cdh for Share payloads and publishes the unsealed tree into out.
func New(manifest, bundle []byte, out string, cdh CDH) (*Helper, error) {
	h := &Helper{bundle: bundle, out: out, cdh: cdh}
	if err := json.Unmarshal(manifest, &h.manifest); err != nil {
		return nil, fmt.Errorf("parse ceremony manifest: %w", err)
	}
	return h, nil
}

// CollectShare fetches one Share payload from the CDH and counts it. Once
// threshold Shares are in, it unseals and publishes the tree and returns true.
func (h *Helper) CollectShare(ctx context.Context) (bool, error) {
	p, err := h.cdh.SharePayload(ctx)
	if err != nil {
		return false, err
	}
	h.shares = append(h.shares, p.Share)
	if len(h.shares) < h.manifest.Threshold {
		return false, nil
	}
	return true, h.publish()
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
