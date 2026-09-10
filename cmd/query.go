package cmd

import (
	"context"

	"github.com/lfallon/sbom-cli/internal/store"
	"github.com/spf13/cobra"
)

type queryOptions struct {
	component string
	version   string
	license   string
}

func newQueryCmd(opts *rootOptions) *cobra.Command {
	q := &queryOptions{}
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Find documents and dependents by component name or by license",
		Long: "Query ingested SBOMs by component name or by license. Exactly one of\n" +
			"--component or --license is required; they cannot be combined.\n\n" +
			"  --component matches the component name exactly, case-insensitive.\n" +
			"  --version narrows a component match to one exact, case-sensitive version.\n" +
			"  --license matches SPDX ids extracted from declared licenses and license\n" +
			"    expressions, case-insensitive, so MIT matches \"MIT OR Apache-2.0\".\n\n" +
			"Every hit names the document that contains the component. Component hits\n" +
			"also list the components that transitively depend on it, nearest first.",
		Example: "  sbom-cli query --component lodash\n" +
			"  sbom-cli query --component lodash --version 4.17.21\n" +
			"  sbom-cli query --license MIT\n" +
			"  sbom-cli --json query --license Apache-2.0",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runQuery(cmd, opts, q)
		},
	}

	f := cmd.Flags()
	f.StringVar(&q.component, "component", "", "component name to look up (exact, case-insensitive)")
	f.StringVar(&q.version, "version", "", "restrict --component to this exact version")
	f.StringVar(&q.license, "license", "", "SPDX license id to look up (exact, case-insensitive)")
	return cmd
}

// validate enforces the flag combinations the store can answer unambiguously.
func (q *queryOptions) validate() error {
	switch {
	case q.component != "" && q.license != "":
		return usageErrorf("--component and --license cannot be combined")
	case q.component == "" && q.license == "":
		return usageErrorf("one of --component or --license is required")
	case q.version != "" && q.component == "":
		return usageErrorf("--version requires --component")
	}
	return nil
}

func runQuery(cmd *cobra.Command, opts *rootOptions, q *queryOptions) error {
	if err := q.validate(); err != nil {
		return err
	}
	return withStore(cmd, opts, func(ctx context.Context, st store.Store) error {
		out := cmd.OutOrStdout()
		if q.license != "" {
			hits, err := st.QueryByLicense(ctx, q.license)
			if err != nil {
				return err
			}
			if opts.json {
				return writeJSON(out, nonNil(hits))
			}
			return renderLicenseHits(out, hits)
		}
		hits, err := st.QueryByComponent(ctx, q.component, q.version)
		if err != nil {
			return err
		}
		if opts.json {
			return writeJSON(out, nonNil(hits))
		}
		return renderComponentHits(out, hits)
	})
}
