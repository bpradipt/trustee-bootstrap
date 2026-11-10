package cli

import (
	"context"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
)

// NewTrusteeBootstrapCmdWith returns the command tree with approve and status
// wired to client (the Bootstrap Helper), dial and startVerifier (the
// operator's own machine) instead of the real network and Operator Verifier.
func NewTrusteeBootstrapCmdWith(
	client *http.Client,
	dial func(ctx context.Context, network, address string) (net.Conn, error),
	startVerifier func(ctx context.Context, address string, share ceremony.ShareFile) (string, func(), error),
) *cobra.Command {
	return newRootCmd(env{client: client, dial: dial, startVerifier: startVerifier})
}
