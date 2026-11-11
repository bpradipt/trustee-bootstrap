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
	"time"

	"github.com/confidential-devhub/trustee-bootstrap/internal/audit"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/relay"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// cdhURL is the sandbox CDH's get-resource API.
const cdhURL = "http://127.0.0.1:8006"

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
	f, err := parseFlags(args)
	if err != nil {
		return err
	}
	// A restart after the rename finds the published tree: nothing to do.
	published, err := helper.Recover(f.out.Dir)
	if err != nil || published {
		return err
	}
	// LOCKED: read each untrusted mount once. The host can swap the files at
	// any time, so the helper never opens them again.
	manifest, err := readCapped(f.manifest)
	if err != nil {
		return fmt.Errorf("read Ceremony Manifest: %w", err)
	}
	bundle, err := readCapped(f.bundle)
	if err != nil {
		return fmt.Errorf("read Sealed Bundle: %w", err)
	}
	h, err := helper.New(manifest, f.manifestSHA256, bundle, f.out, helper.CDH{URL: cdhURL, Client: cdh}, audit.New(os.Stderr))
	if err != nil {
		return err
	}
	l, err := listen("tcp", f.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.proxyPort))
	return h.Serve(l, func() (net.Listener, error) { return listen("tcp", proxyAddr) }, f.deadline, f.limits)
}

// flags are the helper's args. The Kata Agent policy pins every one.
type flags struct {
	manifest, manifestSHA256, bundle, listen string
	out                                      helper.Output
	proxyPort                                int
	deadline                                 time.Duration
	limits                                   relay.Limits
}

func parseFlags(args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("bootstrap-helper", flag.ContinueOnError)
	fs.StringVar(&f.manifest, "manifest", "", "Ceremony Manifest (ceremony.json)")
	fs.StringVar(&f.manifestSHA256, "manifest-sha256", "", "hex SHA-256 of the Ceremony Manifest; required")
	fs.StringVar(&f.bundle, "bundle", "", "Sealed Bundle")
	fs.StringVar(&f.out.Dir, "out", "", "directory to publish Trustee's config tree into")
	fs.IntVar(&f.out.UID, "owner-uid", -1, "Trustee's UID, which gets the published tree; required")
	fs.IntVar(&f.out.GID, "owner-gid", -1, "Trustee's GID, which gets the published tree; required")
	fs.StringVar(&f.listen, "listen", ":8080", "Helper API listen address")
	fs.IntVar(&f.proxyPort, "proxy-port", 8081, "guest-loopback proxy port on 127.0.0.1: the KBS URL in Init-Data")
	fs.DurationVar(&f.deadline, "deadline", 0, "discard accepted Shares and fail after this long; 0 means no deadline")
	limits := relay.LimitFlags(fs)
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	var err error
	if f.limits, err = limits(); err != nil {
		return f, err
	}
	if f.out.Dir == "" {
		return f, errors.New("--out is required")
	}
	// No default: a dropped arg must not hand the tree to whoever runs the
	// helper.
	if f.out.UID < 0 || f.out.GID < 0 {
		return f, errors.New("--owner-uid and --owner-gid are required")
	}
	return f, nil
}

// readCapped reads the file at path, refusing one over seal.MaxSize: the
// Ceremony Manifest and the Sealed Bundle both travel in a ConfigMap.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, seal.MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > seal.MaxSize {
		return nil, fmt.Errorf("%s is over %d bytes", path, seal.MaxSize)
	}
	return b, nil
}
