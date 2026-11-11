// Package audit names the redacted audit events that the Bootstrap Helper
// and the CLI write, one JSON object per line. An event carries indices,
// digests, states, addresses and this module's own error text. It never
// carries a Share, a JWE, a token, an evidence body or a key.
package audit

import (
	"io"
	"log/slog"
	"strings"
)

// The audit events. The message of every record is one of these.
const (
	StateChanged    = "state_changed"    // helper: state; error on FAILED
	ShareAccepted   = "share_accepted"   // helper: index, accepted
	ShareRejected   = "share_rejected"   // helper: index, reason
	RelayOpened     = "relay_opened"     // helper and approve
	RelayClosed     = "relay_closed"     // helper and approve: code, reason or error
	VerifierStarted = "verifier_started" // approve: address
	VerifierStopped = "verifier_stopped" // approve
	ApproveResult   = "approve_result"   // approve: accepted, error
)

// New returns a logger that writes audit records to w.
func New(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}

// Error is err as an audit attribute. It keeps only the first line, so the
// KBS output that a failed Operator Verifier start appends stays out of the
// audit record. A nil err gives the empty Attr, which handlers drop.
func Error(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	first, _, _ := strings.Cut(err.Error(), "\n")
	return slog.String("error", first)
}
