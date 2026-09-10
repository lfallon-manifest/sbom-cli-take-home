package corpus

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lfallon/sbom-cli/internal/store"
)

// generate writes a corpus into a temp dir and returns the dir and its files.
func generate(t *testing.T, cfg Config) (Summary, []string) {
	t.Helper()
	cfg.OutDir = t.TempDir()
	summary, err := Generate(cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(cfg.OutDir, "*.cdx.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return summary, files
}

func TestGenerateWritesOneFilePerDocument(t *testing.T) {
	dir := t.TempDir()

	summary, err := Generate(Config{OutDir: dir, Documents: 3, ComponentsPerDoc: 5, Seed: 1})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.cdx.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("wrote %d files, want 3: %v", len(files), files)
	}
	if summary.Files != 3 {
		t.Errorf("Summary.Files = %d, want 3", summary.Files)
	}
}

func TestSameSeedProducesIdenticalFiles(t *testing.T) {
	cfg := Config{
		Documents: 5, ComponentsPerDoc: 20, Seed: 42,
		Jitter: 0.3, RevisionRate: 0.5, NoSerialRate: 0.2, CycleRate: 0.3, DanglingRate: 0.2,
		Workers: 4,
	}
	_, first := generate(t, cfg)
	_, second := generate(t, cfg)

	if len(first) != len(second) {
		t.Fatalf("file counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if filepath.Base(first[i]) != filepath.Base(second[i]) {
			t.Fatalf("file %d named %s then %s", i, filepath.Base(first[i]), filepath.Base(second[i]))
		}
		a, err := os.ReadFile(first[i])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		b, err := os.ReadFile(second[i])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between runs with the same seed", filepath.Base(first[i]))
		}
	}
}

func TestDifferentSeedProducesDifferentFiles(t *testing.T) {
	cfg := Config{Documents: 2, ComponentsPerDoc: 20}
	cfg.Seed = 1
	_, first := generate(t, cfg)
	cfg.Seed = 2
	_, second := generate(t, cfg)

	a, err := os.ReadFile(first[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	b, err := os.ReadFile(second[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("seeds 1 and 2 produced the same first document")
	}
}

// The corpus exists to exercise the canonical packages table, so the same
// package-versions have to recur across documents rather than each document
// inventing its own.
func TestPackagesConvergeAcrossDocuments(t *testing.T) {
	summary, _ := generate(t, Config{Documents: 40, ComponentsPerDoc: 50, UniverseSize: 400, Seed: 3})

	// The universe plus one primary package-version per application is the ceiling.
	if ceiling := summary.UniverseSize + summary.Documents; summary.DistinctPackages > ceiling {
		t.Errorf("DistinctPackages = %d, above the ceiling of %d", summary.DistinctPackages, ceiling)
	}
	if summary.DistinctPackages*2 >= summary.Components {
		t.Errorf("DistinctPackages = %d against %d components: packages are not converging",
			summary.DistinctPackages, summary.Components)
	}
	if len(summary.TopPackages) != topPackageCount {
		t.Fatalf("TopPackages has %d entries, want %d", len(summary.TopPackages), topPackageCount)
	}
	// The hot head of the distribution is what makes the dependents walk expensive,
	// so the most common package has to reach most documents.
	if hottest := summary.TopPackages[0].Document; hottest < summary.Documents/2 {
		t.Errorf("hottest package is in %d of %d documents, want at least half",
			hottest, summary.Documents)
	}
	for i := 1; i < len(summary.TopPackages); i++ {
		if summary.TopPackages[i-1].Document < summary.TopPackages[i].Document {
			t.Errorf("TopPackages not sorted descending at %d: %+v", i, summary.TopPackages)
		}
	}
}

func TestGeneratedDocumentsIngestCleanly(t *testing.T) {
	const componentsPerDoc = 25
	_, files := generate(t, Config{Documents: 4, ComponentsPerDoc: componentsPerDoc, Seed: 7})

	ctx := context.Background()
	s, err := store.Open(ctx, "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	for _, f := range files {
		res, err := s.Ingest(ctx, f)
		if err != nil {
			t.Fatalf("ingest %s: %v", filepath.Base(f), err)
		}
		if res.AlreadyPresent {
			t.Errorf("%s: AlreadyPresent = true on first ingest", filepath.Base(f))
		}
		// The primary component is stored alongside the components array.
		if want := componentsPerDoc + 1; res.Components != want {
			t.Errorf("%s: Components = %d, want %d", filepath.Base(f), res.Components, want)
		}
		if res.DanglingRefs != 0 {
			t.Errorf("%s: DanglingRefs = %d, want 0", filepath.Base(f), res.DanglingRefs)
		}
		// Every non-primary component hangs off the graph, so there is at least one
		// edge per component in the array.
		if res.Dependencies < componentsPerDoc {
			t.Errorf("%s: Dependencies = %d, want >= %d", filepath.Base(f), res.Dependencies, componentsPerDoc)
		}
	}
}

// The summary is what a scaling run reports, so it has to agree with what the
// store actually stored.
func TestSummaryMatchesIngestTotals(t *testing.T) {
	summary, files := generate(t, Config{
		Documents: 12, ComponentsPerDoc: 40, UniverseSize: 300, Seed: 11,
		Jitter: 0.3, RevisionRate: 0.5, CycleRate: 0.25,
	})

	ctx := context.Background()
	s, err := store.Open(ctx, "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	var components, packages, dependencies int
	for _, f := range files {
		res, err := s.Ingest(ctx, f)
		if err != nil {
			t.Fatalf("ingest %s: %v", filepath.Base(f), err)
		}
		components += res.Components
		packages += res.NewPackages
		dependencies += res.Dependencies
	}

	if len(files) != summary.Files {
		t.Errorf("wrote %d files, summary says %d", len(files), summary.Files)
	}
	if components != summary.Components {
		t.Errorf("store holds %d components, summary says %d", components, summary.Components)
	}
	if packages != summary.DistinctPackages {
		t.Errorf("store holds %d packages, summary says %d", packages, summary.DistinctPackages)
	}
	if dependencies != summary.Dependencies {
		t.Errorf("store holds %d dependency edges, summary says %d", dependencies, summary.Dependencies)
	}
}
