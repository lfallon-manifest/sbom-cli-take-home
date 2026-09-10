// Package cmd wires the sbom-cli command tree. It codes against store.Store so the
// command layer can be tested with a fake.
package cmd

import (
	"context"
	"fmt"

	"github.com/lfallon/sbom-cli/internal/store"
	"github.com/spf13/cobra"
)

// openStore is the seam tests swap for a fake Store.
var openStore = func(ctx context.Context, path string) (store.Store, error) {
	return store.Open(ctx, path)
}

// UsageError marks a flag or argument validation failure; main exits 2 for these.
type UsageError struct {
	msg string
}

func (e *UsageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &UsageError{msg: fmt.Sprintf(format, args...)}
}

// usageArgs wraps a cobra positional-args check so its failures count as usage errors.
func usageArgs(check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := check(cmd, args); err != nil {
			return &UsageError{msg: err.Error()}
		}
		return nil
	}
}

// rootOptions holds the persistent flags shared by every subcommand.
type rootOptions struct {
	dbPath string
	json   bool
}

// NewRootCmd builds a fresh command tree. Tests call it per run so no flag state leaks.
func NewRootCmd() *cobra.Command {
	opts := &rootOptions{}
	root := &cobra.Command{
		Use:   "sbom-cli",
		Short: "Ingest and query CycloneDX SBOMs",
		Long: "sbom-cli ingests CycloneDX 1.6 JSON SBOMs into a local DuckDB file and\n" +
			"answers which documents and packages contain a given component or license.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &UsageError{msg: err.Error()}
	})

	pf := root.PersistentFlags()
	pf.StringVar(&opts.dbPath, "db", "./sbom.duckdb", "DuckDB file to use (created if missing)")
	pf.BoolVar(&opts.json, "json", false, "emit JSON instead of a human-readable table")

	root.AddCommand(newIngestCmd(opts), newQueryCmd(opts))
	return root
}

// Execute runs the CLI against os.Args and returns the command's error, if any.
func Execute() error {
	return NewRootCmd().ExecuteContext(context.Background())
}

// withStore opens the configured store, runs fn against it, and closes it. A Close
// failure is reported only when fn itself succeeded.
func withStore(cmd *cobra.Command, opts *rootOptions, fn func(context.Context, store.Store) error) (err error) {
	ctx := cmd.Context()
	st, err := openStore(ctx, opts.dbPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := st.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close store: %w", cerr)
		}
	}()
	return fn(ctx, st)
}
