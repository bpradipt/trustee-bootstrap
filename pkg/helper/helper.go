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
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"filippo.io/age"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
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
	// A Share payload is a few hundred bytes. A longer answer is cut short
	// and fails to parse.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPayloadSize))
	defer ceremony.Wipe(body)
	if err != nil {
		return p, fmt.Errorf("read Share payload: %w", err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("parse Share payload: %w", err)
	}
	return p, nil
}

// maxPayloadSize caps the CDH answer the helper reads (64 KiB).
const maxPayloadSize = 65536

// State is the Bootstrap Helper's place in its state machine (spec §5).
type State string

// States a status request can observe.
const (
	StateCollecting State = "COLLECTING"
	StateUnsealing  State = "UNSEALING"
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

// Output is where the helper publishes Trustee's config tree, and who owns
// it there: Trustee's UID and GID, pinned in --owner-uid and --owner-gid.
type Output struct {
	Dir      string
	UID, GID int
}

// Helper is one boot's Bootstrap Helper.
type Helper struct {
	manifest     ceremony.Manifest
	bundle       []byte // the only copy of the Sealed Bundle the helper uses
	bundleSHA256 string
	out          Output
	cdh          CDH
	bootID       string
	audit        *slog.Logger  // audit records, each with boot_id and key_id
	relayMu      sync.Mutex    // held by the one open relay
	done         chan struct{} // closed on leaving COLLECTING

	mu       sync.Mutex // guards the fields below
	state    State
	shares   [][]byte
	accepted []int
	rejected []int
}

// New is LOCKED (spec §5): it returns a Helper for the Ceremony Manifest and
// Sealed Bundle bytes, read once from the untrusted mounts. The manifest must
// hash to manifestSHA256, the hex digest that the Kata Agent policy pins in
// --manifest-sha256. The Helper uses only these bytes from here on. It asks
// cdh for Share payloads, publishes the unsealed tree into out and writes
// its audit records to log.
func New(manifest []byte, manifestSHA256 string, bundle []byte, out Output, cdh CDH, log *slog.Logger) (*Helper, error) {
	if got := ceremony.SHA256Hex(manifest); got != manifestSHA256 {
		return nil, fmt.Errorf("Ceremony Manifest sha256 %s does not match --manifest-sha256 %q", got, manifestSHA256)
	}
	h := &Helper{
		bundle:       bundle,
		bundleSHA256: ceremony.SHA256Hex(bundle),
		out:          out,
		cdh:          cdh,
		bootID:       rand.Text(),
		done:         make(chan struct{}),
		state:        StateCollecting,
		accepted:     []int{},
		rejected:     []int{},
	}
	if err := json.Unmarshal(manifest, &h.manifest); err != nil {
		return nil, fmt.Errorf("parse Ceremony Manifest: %w", err)
	}
	if err := h.manifest.Validate(); err != nil {
		return nil, fmt.Errorf("Ceremony Manifest: %w", err)
	}
	h.audit = log.With("boot_id", h.bootID, "key_id", h.manifest.KeyID)
	h.audit.Info(audit.StateChanged, "state", h.state, "threshold", h.manifest.Threshold, "bundle_sha256", h.bundleSHA256)
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
	shares, err := h.accept(p)
	if err != nil || shares == nil {
		return false, err
	}
	// UNSEALING: publish without the lock, so status still answers.
	err = h.publish(shares)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = StatePublished
	if err != nil {
		h.state = StateFailed
	}
	h.audit.Info(audit.StateChanged, "state", h.state, audit.Error(err))
	close(h.done)
	return err == nil, err
}

// accept counts p if it passes the COLLECTING checks, and wipes it if not.
// At threshold it moves to UNSEALING and hands over the Shares; otherwise
// it returns none.
func (h *Helper) accept(p ceremony.SharePayload) ([][]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != StateCollecting {
		ceremony.Wipe(p.Share)
		return nil, fmt.Errorf("unlock already ended: %s", h.state)
	}
	if err := h.check(p); err != nil {
		ceremony.Wipe(p.Share)
		if !slices.Contains(h.rejected, p.Index) {
			h.rejected = append(h.rejected, p.Index)
		}
		h.audit.Info(audit.ShareRejected, "index", p.Index, audit.Error(err))
		return nil, fmt.Errorf("reject Share index %d: %w", p.Index, err)
	}
	h.shares = append(h.shares, p.Share)
	h.accepted = append(h.accepted, p.Index)
	h.audit.Info(audit.ShareAccepted, "index", p.Index, "accepted", len(h.accepted))
	if len(h.shares) < h.manifest.Threshold {
		return nil, nil
	}
	shares := h.shares
	h.shares = nil
	h.state = StateUnsealing
	h.audit.Info(audit.StateChanged, "state", h.state)
	return shares, nil
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
	if p.BundleSHA256 != h.bundleSHA256 {
		return fmt.Errorf("bundle_sha256 %q is not the mounted Sealed Bundle's", p.BundleSHA256)
	}
	return nil
}

// expire ends COLLECTING when --deadline passes: it discards the accepted
// Shares and fails.
func (h *Helper) expire() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state != StateCollecting {
		return
	}
	ceremony.Wipe(h.shares...)
	h.shares = nil
	h.state = StateFailed
	h.audit.Info(audit.StateChanged, "state", h.state, audit.Error(errDeadline))
	close(h.done)
}

var errDeadline = errors.New("deadline passed")

// publish combines shares, then wipes them. It unseals into a staging
// directory beside out, runs the sealed-config checks, marks the tree
// complete, then renames it into place. On failure it wipes the staging
// directory.
func (h *Helper) publish(shares [][]byte) error {
	id, err := ceremony.Combine(shares)
	ceremony.Wipe(shares...)
	if err != nil {
		return err
	}
	staging := stagingDir(h.out.Dir)
	if err := stage(h.bundle, id, staging, h.out); err != nil {
		return errors.Join(err, os.RemoveAll(staging))
	}
	// The commit point: before it a restart wipes staging, after it a
	// restart finds the marked tree.
	if err := rename(staging, h.out.Dir); err != nil {
		return errors.Join(fmt.Errorf("publish tree: %w", err), os.RemoveAll(staging))
	}
	// Past the commit point a restart finds the tree, so the unlock has
	// succeeded whatever the sync says; the record keeps the failure.
	if err := syncPath(filepath.Dir(h.out.Dir)); err != nil {
		h.audit.Warn(audit.PublishUnsynced, audit.Error(err))
	}
	return nil
}

// rename is os.Rename; tests replace it to crash the helper at the commit
// point.
var rename = os.Rename

func stagingDir(out string) string { return out + ".staging" }

// Recover is the helper's first step on start (spec §5). It reports whether
// out already holds the published tree: the completion marker inside it
// proves the rename finished. If not, it wipes any staging directory a crash
// left behind, so the new boot starts with nothing.
func Recover(out string) (published bool, err error) {
	_, err = os.Lstat(filepath.Join(out, CompletionMarker))
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("look for the published tree: %w", err)
	}
	if err := os.RemoveAll(stagingDir(out)); err != nil {
		return false, fmt.Errorf("wipe leftover staging: %w", err)
	}
	return false, nil
}

// stage unseals bundle into staging and checks the tree as Trustee will see
// it at out. A bundle sealed with stock age never had these checks. Then it
// marks the tree complete, hands it to Trustee's UID and GID and syncs every
// file and directory in it.
func stage(bundle []byte, id age.Identity, staging string, out Output) error {
	if err := seal.Unseal(bundle, id, staging); err != nil {
		return err
	}
	if err := verifier.CheckSealedConfig(staging, out.Dir); err != nil {
		return fmt.Errorf("sealed-config checks: %w", err)
	}
	if err := os.WriteFile(filepath.Join(staging, CompletionMarker), nil, 0o600); err != nil {
		return fmt.Errorf("write completion marker: %w", err)
	}
	if err := chownTree(staging, out.UID, out.GID); err != nil {
		return fmt.Errorf("hand the tree to Trustee: %w", err)
	}
	if err := syncTree(staging); err != nil {
		return fmt.Errorf("sync staging: %w", err)
	}
	return nil
}

// chownTree gives dir and everything in it to uid and gid. Unseal made
// only directories and regular files, so no link is followed.
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		return errors.Join(err, os.Lchown(path, uid, gid))
	})
}

// syncTree fsyncs dir and everything in it.
func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		return errors.Join(err, syncPath(path))
	})
}

// syncPath fsyncs one file or directory. If Open fails, f is nil, and the
// nil File's methods return os.ErrInvalid.
func syncPath(path string) error {
	f, err := os.Open(path)
	return errors.Join(err, f.Sync(), f.Close())
}
