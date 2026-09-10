// Command sbom-cli ingests CycloneDX SBOMs into DuckDB and queries them.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lfallon/sbom-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "sbom-cli: %v\n", err)
		var usage *cmd.UsageError
		if errors.As(err, &usage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
