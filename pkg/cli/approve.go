package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"

	"github.com/coder/websocket"
	"github.com/spf13/cobra"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
)

// verifierAddress is where approve starts the Operator Verifier: loopback
// only, on a random port. Every remote connection approve makes is outbound.
const verifierAddress = "127.0.0.1:0"

// env is how approve and status reach the outside world.
type env struct {
	client *http.Client // reaches the Bootstrap Helper
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	// startVerifier starts the Operator Verifier on address, serving the
	// Share payload for share. It returns the address it listens on.
	startVerifier func(ctx context.Context, address string, share ceremony.ShareFile) (string, func(), error)
}

func defaultEnv() env {
	return env{client: http.DefaultClient, dial: (&net.Dialer{}).DialContext, startVerifier: noVerifier}
}

// noVerifier refuses to run: until Bootstrap Attestation is wired in, approve
// has nothing that may release a Share.
func noVerifier(context.Context, string, ceremony.ShareFile) (string, func(), error) {
	return "", nil, errors.New("this build has no Operator Verifier")
}

func newApproveCmd(e env) *cobra.Command {
	var endpoint, shareFile string
	cmd := &cobra.Command{
		Use:   "approve --endpoint URL --share-file FILE",
		Short: "Release your Share to the Trustee CVM through the Bootstrap Helper's relay",
		Long: "Start the Operator Verifier on 127.0.0.1, open the relay to the Bootstrap Helper and " +
			"serve its attestation through it. Prints \"accepted\" once the helper accepts the Share; " +
			"that does not mean Trustee is running.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			share, err := readShareFile(shareFile)
			if err != nil {
				return err
			}
			if err := e.approve(cmd.Context(), endpoint, share); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "accepted")
			return err
		},
	}
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Bootstrap Helper URL (http:// or https://)")
	cmd.Flags().StringVar(&shareFile, "share-file", "", "your Share file")
	requireFlags(cmd, "endpoint", "share-file")
	return cmd
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

func readShareFile(path string) (ceremony.ShareFile, error) {
	var s ceremony.ShareFile
	b, err := os.ReadFile(path)
	if err != nil {
		return s, fmt.Errorf("read Share file: %w", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("parse Share file: %w", err)
	}
	return s, nil
}

// approve runs one Security Operator's flow (spec §4). It never prints the Share.
func (e env) approve(ctx context.Context, endpoint string, share ceremony.ShareFile) error {
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
	addr, stop, err := e.startVerifier(ctx, verifierAddress, share)
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
	})
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
