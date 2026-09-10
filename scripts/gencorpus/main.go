// Command gencorpus writes a large synthetic corpus of CycloneDX 1.6 SBOMs for
// scale testing. The output is deliberately not committed: the defaults produce
// hundreds of megabytes. Regenerate it with the same --seed to get the same
// bytes back.
//
//	go run ./scripts/gencorpus --out examples-large
//	./sbom-cli --db ./large.duckdb ingest examples-large/*.cdx.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/lfallon/sbom-cli/internal/corpus"
)

// manifestName describes the generated corpus. The .json suffix deliberately
// avoids .cdx.json so an `ingest *.cdx.json` glob does not pick it up.
const manifestName = "corpus-manifest.json"

// manifest records how a corpus was generated and what it contains, so a run
// can be reproduced and so there are known packages to query.
type manifest struct {
	GeneratedAt string         `json:"generatedAt"`
	Command     string         `json:"command"`
	Config      corpus.Config  `json:"config"`
	Summary     corpus.Summary `json:"summary"`
	Duration    string         `json:"duration"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gencorpus:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("gencorpus", flag.ContinueOnError)
	fs.SetOutput(stdout)
	var (
		cfg     corpus.Config
		force   = fs.Bool("force", false, "write into a non-empty output directory")
		quiet   = fs.Bool("quiet", false, "suppress progress output")
		outDir  = fs.String("out", "examples-large", "directory to write the corpus into")
		docs    = fs.Int("documents", 2500, "number of applications to generate")
		comps   = fs.Int("components", 800, "mean components per document")
		univ    = fs.Int("universe", 0, "distinct package-versions to draw from (0 derives one)")
		seed    = fs.Int64("seed", 1, "seed; the same seed regenerates the same bytes")
		workers = fs.Int("workers", 0, "parallel writers (0 means one per CPU)")
	)
	jitter := fs.Float64("jitter", 0.35, "fraction to vary each document's component count by")
	revisions := fs.Float64("revision-rate", 0.15, "fraction of applications that also emit a second revision")
	noSerial := fs.Float64("no-serial-rate", 0.05, "fraction of documents emitted without a serialNumber")
	cycles := fs.Float64("cycle-rate", 0.05, "fraction of documents containing a dependency cycle")
	dangling := fs.Float64("dangling-rate", 0.03, "fraction of documents containing a dangling dependency ref")
	fs.Usage = func() {
		fmt.Fprintln(stdout, "gencorpus writes a synthetic CycloneDX SBOM corpus for scale testing.")
		fmt.Fprintln(stdout, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg = corpus.Config{
		OutDir:           *outDir,
		Documents:        *docs,
		ComponentsPerDoc: *comps,
		UniverseSize:     *univ,
		Seed:             *seed,
		Workers:          *workers,
		Jitter:           *jitter,
		RevisionRate:     *revisions,
		NoSerialRate:     *noSerial,
		CycleRate:        *cycles,
		DanglingRate:     *dangling,
	}
	if err := checkOutDir(cfg.OutDir, *force); err != nil {
		return err
	}
	if !*quiet {
		cfg.Progress = progressPrinter(stdout)
	}

	fmt.Fprintf(stdout, "generating %d documents of ~%d components into %s (seed %d)\n",
		cfg.Documents, cfg.ComponentsPerDoc, cfg.OutDir, cfg.Seed)
	start := time.Now()
	summary, err := corpus.Generate(cfg)
	if err != nil {
		return err
	}
	elapsed := time.Since(start)

	if err := writeManifest(cfg, summary, elapsed, args); err != nil {
		return err
	}
	reportSummary(stdout, cfg, summary, elapsed)
	return nil
}

// checkOutDir refuses to scribble into a directory that already holds files,
// so pointing --out at examples/ by mistake cannot destroy the fixtures.
func checkOutDir(dir string, force bool) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	if len(entries) > 0 && !force {
		return fmt.Errorf("%s already holds %d entries; rerun with --force to overwrite", dir, len(entries))
	}
	return nil
}

func progressPrinter(w io.Writer) func(done, total int) {
	last := time.Now()
	return func(done, total int) {
		if done != total && time.Since(last) < time.Second {
			return
		}
		last = time.Now()
		fmt.Fprintf(w, "\r  %d/%d documents", done, total)
		if done == total {
			fmt.Fprintln(w)
		}
	}
}

func writeManifest(cfg corpus.Config, summary corpus.Summary, elapsed time.Duration, args []string) error {
	m := manifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Command:     "go run ./scripts/gencorpus " + fmt.Sprint(args),
		Config:      cfg,
		Summary:     summary,
		Duration:    elapsed.Round(time.Millisecond).String(),
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	path := filepath.Join(cfg.OutDir, manifestName)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func reportSummary(w io.Writer, cfg corpus.Config, s corpus.Summary, elapsed time.Duration) {
	fmt.Fprintf(w, "\nwrote %s in %s (%s)\n", plural(s.Files, "file"), elapsed.Round(time.Millisecond), humanBytes(s.Bytes))
	fmt.Fprintf(w, "  documents:         %d (%d revisions)\n", s.Documents, s.Revisions)
	fmt.Fprintf(w, "  components:        %d occurrences\n", s.Components)
	fmt.Fprintf(w, "  dependency edges:  %d\n", s.Dependencies)
	fmt.Fprintf(w, "  package-versions:  %d distinct (%d drawn from a universe of %d, plus one primary per application)\n",
		s.DistinctPackages, s.DistinctPackages-s.Documents, s.UniverseSize)
	if s.DistinctPackages > 0 {
		fmt.Fprintf(w, "  reuse factor:      %.1f component occurrences per package-version\n",
			float64(s.Components)/float64(s.DistinctPackages))
	}
	if len(s.TopPackages) == 0 {
		return
	}
	fmt.Fprintln(w, "\nmost widely used package-versions:")
	for _, p := range s.TopPackages {
		fmt.Fprintf(w, "  %-52s %s\n", p.Package, plural(p.Document, "document"))
	}
	fmt.Fprintf(w, "\nnext steps:\n")
	fmt.Fprintf(w, "  ./sbom-cli --db ./large.duckdb ingest %s\n", filepath.Join(cfg.OutDir, "*.cdx.json"))
	fmt.Fprintf(w, "  ./sbom-cli --db ./large.duckdb query --component %s   # in %s\n",
		packageName(s.TopPackages[0].Package), plural(s.TopPackages[0].Document, "document"))
	if len(s.RarePackages) > 0 {
		fmt.Fprintf(w, "  ./sbom-cli --db ./large.duckdb query --component %s   # in %s\n",
			packageName(s.RarePackages[0].Package), plural(s.RarePackages[0].Document, "document"))
	}
	fmt.Fprintf(w, "  ./sbom-cli --db ./large.duckdb query --license GPL-3.0-only\n")
	fmt.Fprintf(w, "\n%s records the full configuration and both ends of the reuse distribution.\n",
		filepath.Join(cfg.OutDir, manifestName))
}

// packageName trims the trailing @version from a "name@version" label.
func packageName(label string) string {
	if i := lastAt(label); i > 0 {
		return label[:i]
	}
	return label
}

func lastAt(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return i
		}
	}
	return -1
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, suffixes := float64(n), []string{"KiB", "MiB", "GiB", "TiB"}
	for _, suffix := range suffixes {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f %s", value, suffixes[len(suffixes)-1])
}
