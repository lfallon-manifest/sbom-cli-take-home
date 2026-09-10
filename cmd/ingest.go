package cmd

import (
	"context"

	"github.com/lfallon/sbom-cli/internal/store"
	"github.com/spf13/cobra"
)

func newIngestCmd(opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "ingest <sbom-file>...",
		Short: "Ingest one or more CycloneDX 1.6 JSON SBOMs into the database",
		Long: "Parse CycloneDX 1.6 JSON SBOMs and store each document, its components,\n" +
			"licenses and dependency graph. Files are ingested in order, each in its own\n" +
			"transaction, and the first failure stops the run. Re-ingesting a byte-identical\n" +
			"file is a no-op.",
		Example: "  sbom-cli ingest examples/web-frontend.cdx.json\n" +
			"  sbom-cli ingest examples/*.cdx.json\n" +
			"  sbom-cli --db ./team.duckdb --json ingest examples/api-service.cdx.json",
		Args: usageArgs(cobra.MinimumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIngest(cmd, opts, args)
		},
	}
}

// runIngest opens the store once and ingests each path in order. Human output is
// written per file as it completes; JSON output is one array written at the end.
func runIngest(cmd *cobra.Command, opts *rootOptions, paths []string) error {
	return withStore(cmd, opts, func(ctx context.Context, st store.Store) error {
		results := make([]store.IngestResult, 0, len(paths))
		for _, path := range paths {
			res, err := st.Ingest(ctx, path)
			if err != nil {
				return err
			}
			results = append(results, res)
			if !opts.json {
				if err := renderIngest(cmd.OutOrStdout(), res); err != nil {
					return err
				}
			}
		}
		if opts.json {
			return writeJSON(cmd.OutOrStdout(), results)
		}
		return nil
	})
}
