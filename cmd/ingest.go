package cmd

import (
	"context"

	"github.com/lfallon/sbom-cli/internal/store"
	"github.com/spf13/cobra"
)

func newIngestCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "ingest <sbom-file>",
		Short: "Ingest a CycloneDX 1.6 JSON SBOM into the database",
		Long: "Parse one CycloneDX 1.6 JSON SBOM and store its document, components,\n" +
			"licenses and dependency graph. Re-ingesting a byte-identical file is a no-op.",
		Example: "  sbom-cli ingest examples/web-frontend.cdx.json\n" +
			"  sbom-cli --db ./team.duckdb --json ingest examples/api-service.cdx.json",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIngest(cmd, opts, args[0])
		},
	}
}

func runIngest(cmd *cobra.Command, opts *rootOptions, path string) error {
	return withStore(cmd, opts, func(ctx context.Context, st store.Store) error {
		res, err := st.Ingest(ctx, path)
		if err != nil {
			return err
		}
		if opts.json {
			return writeJSON(cmd.OutOrStdout(), res)
		}
		return renderIngest(cmd.OutOrStdout(), res)
	})
}
