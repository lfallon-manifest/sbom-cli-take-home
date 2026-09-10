// Package corpus generates a large synthetic collection of CycloneDX 1.6 JSON
// SBOMs for scale testing. Output is deterministic for a given configuration:
// the same seed produces byte-identical files, so a benchmark can be rerun and
// re-ingesting the corpus is a no-op.
package corpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
)

// defaultUniverseDivisor sets how many component occurrences share one
// package-version when Config.UniverseSize is left at zero. Real fleets reuse
// the same dependencies heavily, and the schema stores each package-version
// once, so the universe is much smaller than the component count.
const defaultUniverseDivisor = 50

// Config describes the corpus to generate. The zero value of every rate
// disables that behavior, which keeps tests exact; the CLI supplies the
// realistic defaults.
type Config struct {
	OutDir           string
	Documents        int
	ComponentsPerDoc int
	Jitter           float64 // fraction of ComponentsPerDoc to vary each document by
	Seed             int64
	Workers          int // 0 means one per CPU
	UniverseSize     int // distinct package-versions to draw from; 0 derives one
	RevisionRate     float64
	NoSerialRate     float64
	CycleRate        float64
	DanglingRate     float64
	// Progress, if set, is called as documents complete. It shapes reporting, not
	// the corpus, so it stays out of a serialized Config.
	Progress func(documents, total int) `json:"-"`
}

// PackageCount is one package-version and the number of documents it appears in.
type PackageCount struct {
	Package  string `json:"package"`
	Document int    `json:"documents"`
}

// Summary reports what one Generate call produced.
type Summary struct {
	Files            int   `json:"files"`
	Documents        int   `json:"documents"`
	Revisions        int   `json:"revisions"`
	Components       int   `json:"components"`
	Dependencies     int   `json:"dependencies"`
	UniverseSize     int   `json:"universeSize"`
	DistinctPackages int   `json:"distinctPackages"`
	Bytes            int64 `json:"bytes"`
	// TopPackages and RarePackages are the two ends of the reuse distribution,
	// which is what a query benchmark needs: a package in nearly every document
	// and one in almost none.
	TopPackages  []PackageCount `json:"topPackages"`
	RarePackages []PackageCount `json:"rarePackages"`
}

func (c Config) validate() error {
	switch {
	case c.OutDir == "":
		return fmt.Errorf("OutDir is required")
	case c.Documents <= 0:
		return fmt.Errorf("Documents must be positive, got %d", c.Documents)
	case c.ComponentsPerDoc <= 0:
		return fmt.Errorf("ComponentsPerDoc must be positive, got %d", c.ComponentsPerDoc)
	}
	return nil
}

// universeSize derives a pool big enough that no single document holds a
// noticeable share of it, while still small enough that package-versions recur
// heavily across the corpus.
func (c Config) universeSize() int {
	if c.UniverseSize > 0 {
		return c.UniverseSize
	}
	return max(64, 10*c.ComponentsPerDoc, c.Documents*c.ComponentsPerDoc/defaultUniverseDivisor)
}

func (c Config) workers() int {
	if c.Workers > 0 {
		return c.Workers
	}
	return runtime.NumCPU()
}

// docResult is one finished document, reported back to the aggregator.
type docResult struct {
	files      int
	revisions  int
	components int
	edges      int
	bytes      int64
	picks      []int32
	err        error
}

// Generate writes the corpus described by cfg into cfg.OutDir. Documents are
// built and written in parallel; each document's content depends only on the
// seed and its index, so the result does not depend on scheduling.
func Generate(cfg Config) (Summary, error) {
	if err := cfg.validate(); err != nil {
		return Summary{}, err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return Summary{}, fmt.Errorf("create %s: %w", cfg.OutDir, err)
	}
	u, err := buildUniverse(cfg.universeSize(), cfg.Seed)
	if err != nil {
		return Summary{}, err
	}

	jobs := make(chan int)
	results := make(chan docResult, cfg.workers())
	done := make(chan struct{})

	go func() {
		defer close(jobs)
		for i := range cfg.Documents {
			select {
			case jobs <- i:
			case <-done:
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(cfg.workers())
	for range cfg.workers() {
		go func() {
			defer wg.Done()
			for index := range jobs {
				results <- writeDocumentSet(u, cfg, index)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	summary, err := aggregate(cfg, u, results, done)
	if err != nil {
		return Summary{}, err
	}
	return summary, nil
}

// writeDocumentSet builds document index and its revision, if it has one, and
// writes them to disk.
func writeDocumentSet(u *universe, cfg Config, index int) docResult {
	doc := buildDocument(u, cfg, index)
	res := docResult{files: 1, components: len(doc.bom.Components) + 1, edges: doc.edges, picks: doc.picks}

	n, err := writeDocument(documentPath(cfg.OutDir, index, 1), &doc.bom)
	if err != nil {
		return docResult{err: err}
	}
	res.bytes = n

	// A revision needs a serial number to be a revision rather than a new document.
	if cfg.RevisionRate <= 0 || doc.bom.SerialNumber == "" || revisionRoll(cfg, index) >= cfg.RevisionRate {
		return res
	}
	rev := revise(u, cfg, doc, index)
	n, err = writeDocument(documentPath(cfg.OutDir, index, rev.bom.Version), &rev.bom)
	if err != nil {
		return docResult{err: err}
	}
	res.files++
	res.revisions++
	res.components += len(rev.bom.Components) + 1
	res.edges += rev.edges
	res.bytes += n
	res.picks = append(res.picks, rev.picks...)
	return res
}

func documentPath(dir string, index, version int) string {
	if version > 1 {
		return filepath.Join(dir, fmt.Sprintf("app-%06d-r%d.cdx.json", index+1, version))
	}
	return filepath.Join(dir, fmt.Sprintf("app-%06d.cdx.json", index+1))
}

func writeDocument(path string, bom *documentJSON) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)
	if err := json.NewEncoder(w).Encode(bom); err != nil {
		return 0, fmt.Errorf("encode %s: %w", path, err)
	}
	if err := w.Flush(); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.Size(), nil
}

// aggregate drains the worker results into a Summary, closing done on the first
// error so the producer and workers can stop.
func aggregate(cfg Config, u *universe, results <-chan docResult, done chan struct{}) (Summary, error) {
	summary := Summary{UniverseSize: len(u.packages)}
	counts := make([]int32, len(u.packages))
	var firstErr error

	for res := range results {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
				close(done)
			}
			continue
		}
		if firstErr != nil {
			continue
		}
		summary.Files += res.files
		summary.Documents++
		summary.Revisions += res.revisions
		summary.Components += res.components
		summary.Dependencies += res.edges
		summary.Bytes += res.bytes
		for _, p := range res.picks {
			counts[p]++
		}
		if cfg.Progress != nil {
			cfg.Progress(summary.Documents, cfg.Documents)
		}
	}
	if firstErr != nil {
		return Summary{}, firstErr
	}
	drawn, order := packageStats(u, counts)
	// Each application contributes its own primary package-version on top of the
	// universe entries it draws; a revision reuses its application's primary.
	summary.DistinctPackages = drawn + summary.Documents
	summary.TopPackages = packageCounts(u, counts, order, false)
	summary.RarePackages = packageCounts(u, counts, order, true)
	return summary, nil
}

// topPackageCount is how many of the most widely used package-versions the
// summary reports, so a scaling run has known hot packages to query.
const topPackageCount = 10

// packageStats returns how many universe entries were drawn at all, and those
// entries ordered from most to least used.
func packageStats(u *universe, counts []int32) (distinct int, order []int) {
	order = make([]int, 0, len(counts))
	for i, c := range counts {
		if c > 0 {
			distinct++
			order = append(order, i)
		}
	}
	sort.Slice(order, func(a, b int) bool {
		if counts[order[a]] != counts[order[b]] {
			return counts[order[a]] > counts[order[b]]
		}
		return u.packages[order[a]].label() < u.packages[order[b]].label()
	})
	return distinct, order
}

// packageCounts renders one end of the ordered distribution: the head, or the
// tail reversed so it reads from rarest upwards.
func packageCounts(u *universe, counts []int32, order []int, tail bool) []PackageCount {
	n := min(topPackageCount, len(order))
	picked := order[:n]
	if tail {
		picked = order[len(order)-n:]
	}
	out := make([]PackageCount, 0, n)
	for i := range picked {
		idx := picked[i]
		if tail {
			idx = picked[len(picked)-1-i]
		}
		out = append(out, PackageCount{Package: u.packages[idx].label(), Document: int(counts[idx])})
	}
	return out
}
