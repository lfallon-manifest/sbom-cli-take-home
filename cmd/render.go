package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/lfallon/sbom-cli/internal/store"
)

var (
	componentHeader = []string{"DOCUMENT", "SERIAL", "VER", "COMPONENT", "PACKAGE", "DEPENDENTS"}
	licenseHeader   = []string{"DOCUMENT", "SERIAL", "VER", "COMPONENT", "LICENSE", "DECLARED"}
)

// docKey identifies one ingested document for the "across N document(s)" count.
type docKey struct {
	serial  string
	version int
	name    string
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// nonNil keeps an empty result rendering as [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func renderIngest(w io.Writer, r store.IngestResult) error {
	serial := r.SerialNumber
	if serial == "" {
		serial = "(none)"
	}
	if r.AlreadyPresent {
		_, err := fmt.Fprintf(w, "Already ingested %s (serial %s, version %d); no changes.\n",
			r.DocumentName, serial, r.Version)
		return err
	}
	_, err := fmt.Fprintf(w, "Ingested %s (serial %s, version %d)\n"+
		"  components: %d   new packages: %d   dependency edges: %d   dangling refs: %d\n",
		r.DocumentName, serial, r.Version,
		r.Components, r.NewPackages, r.Dependencies, r.DanglingRefs)
	return err
}

func renderComponentHits(w io.Writer, hits []store.ComponentHit) error {
	rows := make([][]string, 0, len(hits))
	docs := make(map[docKey]struct{})
	for _, h := range hits {
		docs[docKey{h.DocumentSerial, h.DocumentVersion, h.DocumentName}] = struct{}{}
		rows = append(rows, []string{
			orDash(h.DocumentName),
			orDash(h.DocumentSerial),
			strconv.Itoa(h.DocumentVersion),
			nameAtVersion(h.ComponentName, h.ComponentVersion),
			h.PackageKey,
			joinOrDash(h.Dependents),
		})
	}
	return renderTable(w, componentHeader, rows, len(docs))
}

func renderLicenseHits(w io.Writer, hits []store.LicenseHit) error {
	rows := make([][]string, 0, len(hits))
	docs := make(map[docKey]struct{})
	for _, h := range hits {
		docs[docKey{h.DocumentSerial, h.DocumentVersion, h.DocumentName}] = struct{}{}
		rows = append(rows, []string{
			orDash(h.DocumentName),
			orDash(h.DocumentSerial),
			strconv.Itoa(h.DocumentVersion),
			nameAtVersion(h.ComponentName, h.ComponentVersion),
			h.MatchedLicense,
			firstNonEmpty(h.RawExpression, h.MatchedLicense),
		})
	}
	return renderTable(w, licenseHeader, rows, len(docs))
}

// renderTable prints an aligned table followed by a hit/document summary, or
// "No matches." when there are no rows.
func renderTable(w io.Writer, header []string, rows [][]string, docCount int) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No matches.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%d hit(s) across %d document(s).\n", len(rows), docCount)
	return err
}

func nameAtVersion(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func joinOrDash(parts []string) string {
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
