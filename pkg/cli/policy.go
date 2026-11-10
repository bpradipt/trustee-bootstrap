package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-devhub/trustee-bootstrap/pkg/ceremony"
	"github.com/confidential-devhub/trustee-bootstrap/pkg/policy"
)

func newPolicyBuildCmd() *cobra.Command {
	var initData, refValues, manifestPath, shareFile, outDir string
	var in policy.Input
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Write your Operator Policy and your Operator Verifier's resource policy",
		Long: "Compute the Init-Data digest from the reviewed Init-Data TOML, check your Share against the " +
			"Ceremony Manifest, and write " + policy.PolicyFile + " and " + policy.ResourcePolicyFile +
			" into --out-dir, using the claim profile of each accepted TEE type.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			if in.InitData, err = os.ReadFile(initData); err != nil {
				return fmt.Errorf("read Init-Data: %w", err)
			}
			if in.ReferenceValues, err = readJSONFile[map[string][]string](refValues, "reference values"); err != nil {
				return err
			}
			if in.Manifest, err = readJSONFile[ceremony.Manifest](manifestPath, "ceremony manifest"); err != nil {
				return err
			}
			if in.Share, err = readJSONFile[ceremony.ShareFile](shareFile, "Share file"); err != nil {
				return err
			}
			p, err := policy.Build(in)
			if err != nil {
				return err
			}
			if err := policy.Write(outDir, p); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "init_data_sha256 %s\n", p.InitDataSHA256)
			return err
		},
	}
	cmd.Flags().StringVar(&initData, "init-data", "", "the reviewed Init-Data TOML")
	cmd.Flags().StringVar(&refValues, "reference-values", "", `JSON reference values by name, e.g. {"trusted_aks": ["…"]}`)
	cmd.Flags().StringSliceVar(&in.AcceptTEE, "accept-tee", nil, "TEE types to accept (tpm)")
	cmd.Flags().StringVar(&in.BundleSHA256, "bundle-sha256", "", "hex SHA-256 of the Approved Bundle")
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "Ceremony Manifest")
	cmd.Flags().StringVar(&shareFile, "share-file", "", "your Share file")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory for the Operator Policy")
	requireFlags(cmd, "init-data", "reference-values", "accept-tee", "bundle-sha256", "manifest", "share-file", "out-dir")
	return cmd
}
