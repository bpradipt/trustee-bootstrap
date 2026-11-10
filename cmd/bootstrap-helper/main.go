// Command bootstrap-helper is the Bootstrap Helper: the Trustee CVM's init
// container that collects Shares through the relay and publishes Trustee's
// unsealed config tree.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/helper"
)

// cdhURL is the sandbox CDH's get-resource API.
const cdhURL = "http://127.0.0.1:8006"

func main() {
	os.Exit(run(os.Args[1:], net.Listen))
}

// run starts the helper with listen standing in for net.Listen and returns
// the exit code: 0 once the tree is published, 1 on any failure.
func run(args []string, listen func(network, address string) (net.Listener, error)) int {
	if err := serve(args, listen); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap-helper:", err)
		return 1
	}
	return 0
}

func serve(args []string, listen func(network, address string) (net.Listener, error)) error {
	fs := flag.NewFlagSet("bootstrap-helper", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "", "Ceremony Manifest (ceremony.json)")
	bundlePath := fs.String("bundle", "", "Sealed Bundle")
	out := fs.String("out", "", "directory to publish Trustee's config tree into")
	addr := fs.String("listen", ":8080", "Helper API listen address")
	proxyPort := fs.Int("proxy-port", 8081, "guest-loopback proxy port on 127.0.0.1: the KBS URL in Init-Data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manifest, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read ceremony manifest: %w", err)
	}
	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read sealed bundle: %w", err)
	}
	h, err := helper.New(manifest, bundle, *out, helper.CDH{URL: cdhURL, Client: http.DefaultClient})
	if err != nil {
		return err
	}
	l, err := listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(*proxyPort))
	return h.Serve(l, func() (net.Listener, error) { return listen("tcp", proxyAddr) })
}
