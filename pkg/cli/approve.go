package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/coder/websocket"
	"github.com/spf13/cobra"

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
	startVerifier func(ctx context.Context, address string, opts verifier.Options) (string, func(), error)
}

func defaultEnv() env {
	rt := verifier.Runtime{Engine: verifier.DefaultEngine(), Listen: net.Listen, Client: http.DefaultClient}
	return env{client: http.DefaultClient, dial: (&net.Dialer{}).DialContext, startVerifier: rt.Start}
}

func newApproveCmd(e env) *cobra.Command {
	var endpoint, policyDir, shareFile, kbsBinary string
	limits := relay.DefaultLimits()
	cmd := &cobra.Command{
		Use:   "approve --endpoint URL --policy DIR --share-file FILE",
		Short: "Release your Share to the Trustee CVM through the Bootstrap Helper's relay",
		Long: "Check your Share against your Operator Policy, start the Operator Verifier on 127.0.0.1, " +
			"open the relay to the Bootstrap Helper and serve its attestation through it. Prints " +
			"\"accepted\" once the helper accepts the Share; that does not mean Trustee is running.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := limits.Check(); err != nil {
				return err
			}
			share, opts, err := loadApproval(policyDir, shareFile)
			if err != nil {
				return err
			}
			opts.KBSBinary = kbsBinary
			// SIGINT and SIGTERM cancel the context, so the Operator
			// Verifier stops and its run directory goes (AT-18).
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := e.approve(ctx, endpoint, share, opts, limits); err != nil {
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
	cmd.Flags().DurationVar(&limits.Idle, "relay-idle-timeout", limits.Idle, "end the relay after this long with no traffic; may be lowered, not raised")
	cmd.Flags().DurationVar(&limits.Total, "relay-total-timeout", limits.Total, "end the relay after this long; may be lowered, not raised")
	requireFlags(cmd, "endpoint", "policy", "share-file")
	return cmd
}

// loadApproval reads the Share file and the Operator Policy and checks the
// Share against its Share Commitment, before anything starts.
func loadApproval(policyDir, shareFile string) (ceremony.ShareFile, verifier.Options, error) {
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
	return share, verifier.Options{
		ResourcePolicy:  p.ResourcePolicy,
		ReferenceValues: p.ReferenceValues,
		SharePayload:    payload,
	}, nil
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

// approve runs one Security Operator's flow (spec §4) within limits. It never
// prints the Share.
func (e env) approve(ctx context.Context, endpoint string, share ceremony.ShareFile, opts verifier.Options, limits relay.Limits) error {
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
	defer stop()
	u, err := url.JoinPath(endpoint, helper.RelayPath)
	if err != nil {
		return fmt.Errorf("relay URL: %w", err)
	}
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client})
	if err != nil {
		return fmt.Errorf("open relay: %w", err)
	}
	defer ws.CloseNow()
	err = relay.Operator(ctx, ws, func(ctx context.Context) (net.Conn, error) {
		return e.dial(ctx, "tcp", addr)
	}, limits)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		return fmt.Errorf("relay ended: %w", err)
	}
	return nil
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
