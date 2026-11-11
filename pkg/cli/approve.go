package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/coder/websocket"
	"github.com/spf13/cobra"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/verifier"
)

// verifierAddress is where approve starts the Operator Verifier: loopback
// only, on a random port. Every remote connection approve makes is outbound.
const verifierAddress = "127.0.0.1:0"

// env is how approve and status reach the outside world.
type env struct {
	client *http.Client // reaches the Bootstrap Helper
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	// startVerifier starts the Operator Verifier on address. It returns the
	// address it listens on.
	startVerifier func(ctx context.Context, address string, opts verifier.Options) (string, func() error, error)
}

// defaultEnv touches nothing outside the process: cococtl builds the tree
// at startup for every command, so the container engine is looked up only
// when approve starts the Operator Verifier.
func defaultEnv() env {
	start := func(ctx context.Context, address string, opts verifier.Options) (string, func() error, error) {
		rt := verifier.Runtime{Engine: verifier.DefaultEngine(), Listen: net.Listen, Client: http.DefaultClient}
		return rt.Start(ctx, address, opts)
	}
	return env{client: http.DefaultClient, dial: (&net.Dialer{}).DialContext, startVerifier: start}
}

func newApproveCmd(e env) *cobra.Command {
	var endpoint, policyDir, shareFile, kbsBinary string
	relayFlags := flag.NewFlagSet("relay", flag.ContinueOnError)
	relayLimits := relay.LimitFlags(relayFlags)
	cmd := &cobra.Command{
		Use:   "approve --endpoint URL --policy DIR --share-file FILE",
		Short: "Release your Share to the Trustee CVM through the Bootstrap Helper's relay",
		Long: "Check your Share against your Operator Policy, start the Operator Verifier on 127.0.0.1, " +
			"open the relay to the Bootstrap Helper and serve its attestation through it. Prints " +
			"\"accepted\" once the Bootstrap Helper accepts the Share; that does not mean Trustee is running.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			limits, err := relayLimits()
			if err != nil {
				return err
			}
			share, opts, err := loadApproval(policyDir, shareFile, cmd.ErrOrStderr())
			// The Operator Verifier has its own copy; wipe ours on the
			// way out, whatever happens.
			defer ceremony.Wipe(share.Share, opts.SharePayload)
			if err != nil {
				return err
			}
			opts.KBSBinary = kbsBinary
			// SIGINT and SIGTERM cancel the context, so the Operator
			// Verifier stops and its run directory goes (AT-18).
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			log := audit.New(cmd.ErrOrStderr()).With("index", share.Index, "key_id", share.KeyID, "endpoint", endpoint)
			err = e.approve(ctx, endpoint, share, opts, limits, log)
			log.Info(audit.ApproveResult, "accepted", err == nil, audit.Error(err))
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "accepted")
			return err
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Bootstrap Helper URL (http:// or https://)")
	cmd.Flags().StringVar(&policyDir, "policy", "", "your Operator Policy directory (policy build --out-dir)")
	cmd.Flags().StringVar(&shareFile, "share-file", "", "your Share file")
	cmd.Flags().StringVar(&kbsBinary, "kbs-binary", "", "run this natively installed kbs instead of the pinned KBS image")
	cmd.Flags().AddGoFlagSet(relayFlags)
	requireFlags(cmd, "endpoint", "policy", "share-file")
	return cmd
}

// untestedWarning is what approve prints for an Operator Policy built with
// --allow-untested-profiles.
const untestedWarning = "warning: this Operator Policy accepts untested claim profiles; it is not a production Operator Policy"

// loadApproval reads the Share file and the Operator Policy and checks the
// Share against its Share Commitment, before anything starts. It writes a
// warning to warn when the policy accepts untested claim profiles.
func loadApproval(policyDir, shareFile string, warn io.Writer) (ceremony.ShareFile, verifier.Options, error) {
	share, err := readJSONFile[ceremony.ShareFile](shareFile, "Share file")
	if err != nil {
		return share, verifier.Options{}, err
	}
	p, err := policy.Load(policyDir)
	if err != nil {
		return share, verifier.Options{}, err
	}
	if err := p.CheckShare(share); err != nil {
		return share, verifier.Options{}, err
	}
	payload, err := json.Marshal(ceremony.SharePayload{ShareFile: share, BundleSHA256: p.BundleSHA256})
	if err != nil {
		return share, verifier.Options{}, fmt.Errorf("encode Share payload: %w", err)
	}
	if p.UntestedProfiles {
		_, err = fmt.Fprintln(warn, untestedWarning)
	}
	return share, verifier.Options{
		ResourcePolicy:  p.ResourcePolicy,
		ReferenceValues: p.ReferenceValues,
		SharePayload:    payload,
	}, err
}

func newStatusCmd(e env) *cobra.Command {
	var endpoint string
	cmd := &cobra.Command{
		Use:   "status --endpoint URL",
		Short: "Print the Bootstrap Helper's status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := e.status(cmd.Context(), endpoint)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Bootstrap Helper URL (http:// or https://)")
	requireFlags(cmd, "endpoint")
	return cmd
}

// approve runs one Security Operator's flow (spec §4) within limits and
// writes its audit records to log. It never prints the Share.
func (e env) approve(ctx context.Context, endpoint string, share ceremony.ShareFile, opts verifier.Options, limits relay.Limits, log *slog.Logger) (err error) {
	st, err := e.status(ctx, endpoint)
	if err != nil {
		return err
	}
	if st.KeyID != share.KeyID {
		return fmt.Errorf("the Bootstrap Helper has key_id %q, the Share file %q", st.KeyID, share.KeyID)
	}
	if slices.Contains(st.Accepted, share.Index) {
		return fmt.Errorf("index %d already accepted this boot", share.Index)
	}
	addr, stop, err := e.startVerifier(ctx, verifierAddress, opts)
	if err != nil {
		return fmt.Errorf("start Operator Verifier: %w", err)
	}
	log.Info(audit.VerifierStarted, "address", addr)
	// A failed wipe leaves the Share payload on this machine: approve fails
	// with it even when the helper accepted the Share.
	defer func() {
		stopErr := stop()
		log.Info(audit.VerifierStopped, audit.Error(stopErr))
		err = errors.Join(err, stopErr)
	}()
	u, err := url.JoinPath(endpoint, helper.RelayPath)
	if err != nil {
		return fmt.Errorf("relay URL: %w", err)
	}
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client})
	if err != nil {
		return fmt.Errorf("open relay: %w", err)
	}
	defer ws.CloseNow()
	log.Info(audit.RelayOpened)
	err = relay.Operator(ctx, ws, func(ctx context.Context) (net.Conn, error) {
		return e.dial(ctx, "tcp", addr)
	}, limits)
	// Only the helper's normal closure says it accepted the Share.
	code := websocket.CloseStatus(err)
	if code == websocket.StatusNormalClosure {
		log.Info(audit.RelayClosed, "code", int(code))
		return nil
	}
	log.Info(audit.RelayClosed, "code", int(code), audit.Error(err))
	return fmt.Errorf("relay ended: %w", err)
}

// status fetches the Bootstrap Helper's status.
func (e env) status(ctx context.Context, endpoint string) (helper.Status, error) {
	var st helper.Status
	u, err := url.JoinPath(endpoint, helper.StatusPath)
	if err != nil {
		return st, fmt.Errorf("status URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return st, fmt.Errorf("build status request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return st, fmt.Errorf("get status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("get status: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, fmt.Errorf("parse status: %w", err)
	}
	return st, nil
}
