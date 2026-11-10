// Command trustee-bootstrap is the standalone trustee-bootstrap CLI.
package main

import (
	"os"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/cli"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run executes the command tree and returns the process exit code.
func run(args []string) int {
	cmd := cli.NewTrusteeBootstrapCmd()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return 1
	}
	return 0
}
