// Command bootstrap-helper is the Bootstrap Helper: the Trustee CVM's init
// container that collects Shares through the relay and publishes Trustee's
// unsealed config tree.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// cdhURL is the sandbox CDH's get-resource API.
const cdhURL = "http://127.0.0.1:8006"

// maxFileSize caps the Ceremony Manifest and the Sealed Bundle: both travel
// in a ConfigMap.
const maxFileSize = seal.MaxSize

func main() {
	os.Exit(run(os.Args[1:], net.Listen, http.DefaultClient))
}

// run starts the helper with listen standing in for net.Listen and cdh as
// the CDH's HTTP client, and returns the exit code: 0 once the tree is
// published, 1 on any failure.
func run(args []string, listen func(network, address string) (net.Listener, error), cdh *http.Client) int {
	if err := serve(args, listen, cdh); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-helper:", err)
		return 1
	}
	return 0
}

func serve(args []string, listen func(network, address string) (net.Listener, error), cdh *http.Client) error {
	fs := flag.NewFlagSet("bootstrap-helper", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "Ceremony Manifest (ceremony.json)")
	manifestSHA256 := fs.String("manifest-sha256", "", "hex SHA-256 of the Ceremony Manifest; required")
	bundlePath := fs.String("bundle", "", "Sealed Bundle")
	out := fs.String("out", "", "directory to publish Trustee's config tree into")
	addr := fs.String("listen", ":8080", "Helper API listen address")
	proxyPort := fs.Int("proxy-port", 8081, "guest-loopback proxy port on 127.0.0.1: the KBS URL in Init-Data")
	deadline := fs.Duration("deadline", 0, "discard accepted Shares and fail after this long; 0 means no deadline")
	limits := relay.DefaultLimits()
	fs.DurationVar(&limits.Idle, "relay-idle-timeout", limits.Idle, "end a relay after this long with no traffic; may be lowered, not raised")
	fs.DurationVar(&limits.Total, "relay-total-timeout", limits.Total, "end a relay after this long; may be lowered, not raised")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := limits.Check(); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	// A restart after the rename finds the published tree: nothing to do.
	published, err := helper.Recover(*out)
	if err != nil || published {
		return err
	}
	// LOCKED: read each untrusted mount once. The host can swap the files at
	// any time, so the helper never opens them again.
	manifest, err := readCapped(*manifestPath)
	if err != nil {
		return fmt.Errorf("read ceremony manifest: %w", err)
	}
	bundle, err := readCapped(*bundlePath)
	if err != nil {
		return fmt.Errorf("read sealed bundle: %w", err)
	}
	h, err := helper.New(manifest, *manifestSHA256, bundle, *out, helper.CDH{URL: cdhURL, Client: cdh}, audit.New(os.Stderr))
	if err != nil {
		return err
	}
	l, err := listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(*proxyPort))
	return h.Serve(l, func() (net.Listener, error) { return listen("tcp", proxyAddr) }, *deadline, limits)
}

// readCapped reads the file at path, refusing one over maxFileSize.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("%s is over %d bytes", path, maxFileSize)
	}
	return b, nil
}
