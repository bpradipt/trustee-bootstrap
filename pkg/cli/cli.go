// Package cli is the trustee-bootstrap command tree. cococtl mounts it as
// `cococtl trustee-bootstrap`; cmd/trustee-bootstrap runs it standalone.
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/seal"
)

// ManifestFile is the Ceremony Manifest's file name.
const ManifestFile = "ceremony.json"

// NewTrusteeBootstrapCmd returns the trustee-bootstrap command tree.
func NewTrusteeBootstrapCmd() *cobra.Command {
	return newRootCmd(defaultEnv())
}

func newRootCmd(e env) *cobra.Command {
	root := &cobra.Command{
		Use:          "trustee-bootstrap",
		Short:        "Unlock Trustee in a confidential VM with K-of-N Security Operators",
		SilenceUsage: true,
	}
	ceremonyCmd := &cobra.Command{Use: "ceremony", Short: "Key Ceremony commands"}
	ceremonyCmd.AddCommand(newSplitCmd())
	policyCmd := &cobra.Command{Use: "policy", Short: "Operator Policy commands"}
	policyCmd.AddCommand(newPolicyBuildCmd())
	root.AddCommand(ceremonyCmd, newSealCmd(), policyCmd, newApproveCmd(e), newStatusCmd(e))
	return root
}

// requireFlags marks flags required; a name that isn't a flag is a bug.
func requireFlags(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

func newSplitCmd() *cobra.Command {
	var (
		threshold int
		holders   []string
		outDir    string
	)
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Generate the bootstrap key pair and write the Share files and Ceremony Manifest",
		Long: "Generate an age identity, split it into one Share per holder and write " +
			"<holder>.share and " + ManifestFile + " into --out-dir. The identity is never written to disk.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, files, err := ceremony.Split(threshold, holders)
			if err != nil {
				return err
			}
			if err := writeCeremony(outDir, m, files); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "key_id %s\nrecipient %s\n", m.KeyID, m.Recipient)
			return err
		},
	}
	cmd.Flags().IntVar(&threshold, "threshold", 0, "Shares needed to unlock (K)")
	cmd.Flags().StringSliceVar(&holders, "holders", nil, "Share holder labels, one Share each (N)")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "directory for the Share files and "+ManifestFile)
	requireFlags(cmd, "threshold", "holders")
	return cmd
}

// writeCeremony writes each file new, so a rerun never overwrites a Share.
func writeCeremony(dir string, m ceremony.Manifest, files []ceremony.ShareFile) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer root.Close()
	if err := writeJSON(root, ManifestFile, m, 0o644); err != nil {
		return err
	}
	for i, f := range files {
		if err := writeJSON(root, m.Shares[i].Holder+".share", f, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(root *os.Root, name string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	_, err = f.Write(append(b, '\n'))
	if err := errors.Join(err, f.Close()); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func newSealCmd() *cobra.Command {
	var manifestPath, output string
	cmd := &cobra.Command{
		Use:   "seal --manifest " + ManifestFile + " --output BUNDLE DIR",
		Short: "Seal a Trustee config tree into a Sealed Bundle and print its SHA-256",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := readJSONFile[ceremony.Manifest](manifestPath, "ceremony manifest")
			if err != nil {
				return err
			}
			digest, err := sealToFile(output, args[0], m.Recipient)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), digest)
			return err
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "Ceremony Manifest")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Sealed Bundle to write")
	requireFlags(cmd, "manifest", "output")
	return cmd
}

// readJSONFile reads the JSON file at path; what names it in errors.
func readJSONFile[T any](path, what string) (T, error) {
	var v T
	b, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("read %s: %w", what, err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return v, fmt.Errorf("parse %s: %w", what, err)
	}
	return v, nil
}

// sealToFile seals dir into output and returns the bundle's hex SHA-256.
func sealToFile(output, dir, recipient string) (string, error) {
	f, err := os.Create(output)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", output, err)
	}
	sum := sha256.New()
	if err := seal.Seal(io.MultiWriter(f, sum), dir, recipient); err != nil {
		return "", errors.Join(err, f.Close())
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", output, err)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
