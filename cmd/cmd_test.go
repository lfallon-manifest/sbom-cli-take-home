package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lfallon/sbom-cli/internal/store"
)

// fakeStore returns canned results and records what the command layer asked for.
type fakeStore struct {
	ingestResult  store.IngestResult
	componentHits []store.ComponentHit
	licenseHits   []store.LicenseHit
	err           error

	openedPath       string
	opens            int
	ingestPaths      []string
	componentName    string
	componentVersion string
	license          string
	closed           bool
}

func (f *fakeStore) Ingest(_ context.Context, path string) (store.IngestResult, error) {
	f.ingestPaths = append(f.ingestPaths, path)
	return f.ingestResult, f.err
}

func (f *fakeStore) QueryByComponent(_ context.Context, name, version string) ([]store.ComponentHit, error) {
	f.componentName, f.componentVersion = name, version
	return f.componentHits, f.err
}

func (f *fakeStore) QueryByLicense(_ context.Context, license string) ([]store.LicenseHit, error) {
	f.license = license
	return f.licenseHits, f.err
}

func (f *fakeStore) Close() error {
	f.closed = true
	return nil
}

// execute runs a fresh command tree against fake, capturing stdout and stderr.
func execute(t *testing.T, fake *fakeStore, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	orig := openStore
	t.Cleanup(func() { openStore = orig })
	openStore = func(_ context.Context, path string) (store.Store, error) {
		fake.opens++
		fake.openedPath = path
		return fake, nil
	}

	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func assertUsageError(t *testing.T, err error, wantMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a usage error, got nil")
	}
	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UsageError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("error %q does not mention %q", err.Error(), wantMsg)
	}
}

var cannedComponentHits = []store.ComponentHit{
	{
		DocumentSerial:   "urn:uuid:1111",
		DocumentVersion:  1,
		DocumentName:     "web-frontend",
		ComponentName:    "lodash",
		ComponentVersion: "4.17.21",
		PackageKey:       "pkg:npm/lodash@4.17.21",
		Purl:             "pkg:npm/lodash@4.17.21",
		Dependents:       []string{"react-scripts@5.0.1", "web-frontend@2.3.0"},
	},
	{
		DocumentSerial:   "",
		DocumentVersion:  1,
		DocumentName:     "api-service",
		ComponentName:    "lodash",
		ComponentVersion: "4.17.21",
		PackageKey:       "generic:lodash@4.17.21",
	},
}

var cannedLicenseHits = []store.LicenseHit{
	{
		DocumentSerial:   "urn:uuid:2222",
		DocumentVersion:  3,
		DocumentName:     "batch-processor",
		ComponentName:    "left-pad",
		ComponentVersion: "1.3.0",
		MatchedLicense:   "MIT",
		RawExpression:    "MIT OR Apache-2.0",
	},
	{
		DocumentSerial:   "urn:uuid:2222",
		DocumentVersion:  3,
		DocumentName:     "batch-processor",
		ComponentName:    "tiny-lib",
		ComponentVersion: "",
		MatchedLicense:   "MIT",
	},
}

func TestQueryRequiresComponentOrLicense(t *testing.T) {
	fake := &fakeStore{}
	_, _, err := execute(t, fake, "query")
	assertUsageError(t, err, "one of --component or --license is required")
	if fake.opens != 0 {
		t.Fatalf("store opened %d time(s) despite usage error", fake.opens)
	}
}

func TestQueryRejectsComponentAndLicense(t *testing.T) {
	_, _, err := execute(t, &fakeStore{}, "query", "--component", "lodash", "--license", "MIT")
	assertUsageError(t, err, "--component and --license cannot be combined")
}

func TestQueryVersionRequiresComponent(t *testing.T) {
	_, _, err := execute(t, &fakeStore{}, "query", "--version", "1.0", "--license", "MIT")
	assertUsageError(t, err, "--version requires --component")
}

func TestQueryRejectsPositionalArgs(t *testing.T) {
	_, _, err := execute(t, &fakeStore{}, "query", "lodash")
	assertUsageError(t, err, "unknown command")
}

func TestQueryUnknownFlagIsUsageError(t *testing.T) {
	_, _, err := execute(t, &fakeStore{}, "query", "--purl", "pkg:npm/x")
	assertUsageError(t, err, "unknown flag")
}

func TestQueryComponentPassesVersionThrough(t *testing.T) {
	t.Run("table", func(t *testing.T) {
		fake := &fakeStore{componentHits: cannedComponentHits}
		out, _, err := execute(t, fake, "query", "--component", "lodash", "--version", "4.17.21")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fake.componentName != "lodash" || fake.componentVersion != "4.17.21" {
			t.Fatalf("store got (%q, %q), want (lodash, 4.17.21)", fake.componentName, fake.componentVersion)
		}
		if !fake.closed {
			t.Fatalf("store was not closed")
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) != 4 {
			t.Fatalf("want header, 2 rows and summary, got %d lines:\n%s", len(lines), out)
		}
		assertColumns(t, lines[0], "DOCUMENT", "SERIAL", "VER", "COMPONENT", "PACKAGE", "DEPENDENTS")
		assertColumns(t, lines[1], "web-frontend", "urn:uuid:1111", "1", "lodash@4.17.21",
			"pkg:npm/lodash@4.17.21", "react-scripts@5.0.1, web-frontend@2.3.0")
		assertColumns(t, lines[2], "api-service", "-", "1", "lodash@4.17.21", "generic:lodash@4.17.21", "-")
		if lines[3] != "2 hit(s) across 2 document(s)." {
			t.Fatalf("summary line = %q", lines[3])
		}
	})

	t.Run("json", func(t *testing.T) {
		fake := &fakeStore{componentHits: cannedComponentHits}
		out, _, err := execute(t, fake, "--json", "query", "--component", "lodash", "--version", "4.17.21")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got []store.ComponentHit
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, out)
		}
		if !reflect.DeepEqual(got, cannedComponentHits) {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, cannedComponentHits)
		}
		if !strings.HasPrefix(out, "[\n  {\n") {
			t.Fatalf("expected indented JSON, got:\n%s", out)
		}
	})
}

func TestQueryLicenseTable(t *testing.T) {
	fake := &fakeStore{licenseHits: cannedLicenseHits}
	out, _, err := execute(t, fake, "query", "--license", "MIT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.license != "MIT" {
		t.Fatalf("store got license %q, want MIT", fake.license)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header, 2 rows and summary, got %d lines:\n%s", len(lines), out)
	}
	assertColumns(t, lines[0], "DOCUMENT", "SERIAL", "VER", "COMPONENT", "LICENSE", "DECLARED")
	assertColumns(t, lines[1], "batch-processor", "urn:uuid:2222", "3", "left-pad@1.3.0", "MIT", "MIT OR Apache-2.0")
	assertColumns(t, lines[2], "batch-processor", "urn:uuid:2222", "3", "tiny-lib", "MIT", "MIT")
	if lines[3] != "2 hit(s) across 1 document(s)." {
		t.Fatalf("summary line = %q", lines[3])
	}
}

func TestQueryNoHitsTableAndJSON(t *testing.T) {
	t.Run("table", func(t *testing.T) {
		out, _, err := execute(t, &fakeStore{componentHits: []store.ComponentHit{}}, "query", "--component", "nope")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "No matches.\n" {
			t.Fatalf("stdout = %q, want \"No matches.\\n\"", out)
		}
	})

	t.Run("json empty slice", func(t *testing.T) {
		out, _, err := execute(t, &fakeStore{licenseHits: []store.LicenseHit{}}, "--json", "query", "--license", "nope")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.TrimSpace(out) != "[]" {
			t.Fatalf("stdout = %q, want []", out)
		}
	})

	t.Run("json nil slice", func(t *testing.T) {
		out, _, err := execute(t, &fakeStore{componentHits: nil}, "--json", "query", "--component", "nope")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.TrimSpace(out) != "[]" {
			t.Fatalf("stdout = %q, want []", out)
		}
	})
}

func TestQueryStoreErrorIsNotUsageError(t *testing.T) {
	boom := errors.New("query by component: not implemented")
	_, _, err := execute(t, &fakeStore{err: boom}, "query", "--component", "lodash")
	if !errors.Is(err, boom) {
		t.Fatalf("want store error %v, got %v", boom, err)
	}
	var ue *UsageError
	if errors.As(err, &ue) {
		t.Fatalf("store error must not be a usage error")
	}
}

func TestIngestPrintsSummary(t *testing.T) {
	fake := &fakeStore{ingestResult: store.IngestResult{
		SerialNumber: "urn:uuid:1111",
		Version:      1,
		DocumentName: "web-frontend",
		Components:   12,
		NewPackages:  7,
		Dependencies: 14,
		DanglingRefs: 1,
	}}
	out, _, err := execute(t, fake, "ingest", "examples/web-frontend.cdx.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(fake.ingestPaths, []string{"examples/web-frontend.cdx.json"}) {
		t.Fatalf("store got paths %q", fake.ingestPaths)
	}
	if !fake.closed {
		t.Fatalf("store was not closed")
	}
	want := "Ingested web-frontend (serial urn:uuid:1111, version 1)\n" +
		"  components: 12   new packages: 7   dependency edges: 14   dangling refs: 1\n"
	if out != want {
		t.Fatalf("stdout:\n%s\nwant:\n%s", out, want)
	}
}

func TestIngestAlreadyPresent(t *testing.T) {
	fake := &fakeStore{ingestResult: store.IngestResult{
		Version:        1,
		DocumentName:   "web-frontend",
		AlreadyPresent: true,
	}}
	out, _, err := execute(t, fake, "ingest", "x.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Already ingested web-frontend (serial (none), version 1); no changes.\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestIngestJSON(t *testing.T) {
	res := store.IngestResult{SerialNumber: "urn:uuid:1111", Version: 2, DocumentName: "api-service", Components: 3}
	out, _, err := execute(t, &fakeStore{ingestResult: res}, "--json", "ingest", "x.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got store.IngestResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if got != res {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, res)
	}
}

func TestIngestRequiresExactlyOneArg(t *testing.T) {
	fake := &fakeStore{}
	_, _, err := execute(t, fake, "ingest")
	assertUsageError(t, err, "accepts 1 arg(s)")
	_, _, err = execute(t, fake, "ingest", "a.json", "b.json")
	assertUsageError(t, err, "accepts 1 arg(s)")
	if fake.opens != 0 {
		t.Fatalf("store opened %d time(s) despite usage error", fake.opens)
	}
}

func TestDBFlagIsPassedToOpen(t *testing.T) {
	fake := &fakeStore{}
	if _, _, err := execute(t, fake, "--db", "/some/path.duckdb", "query", "--component", "x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.openedPath != "/some/path.duckdb" {
		t.Fatalf("openStore got %q, want /some/path.duckdb", fake.openedPath)
	}

	fake = &fakeStore{}
	if _, _, err := execute(t, fake, "query", "--component", "x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.openedPath != "./sbom.duckdb" {
		t.Fatalf("default db path = %q, want ./sbom.duckdb", fake.openedPath)
	}
}

// assertColumns splits a tabwriter line on runs of two or more spaces and compares.
func assertColumns(t *testing.T, line string, want ...string) {
	t.Helper()
	got := splitColumns(line)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("columns = %q, want %q (line %q)", got, want, line)
	}
}

func splitColumns(line string) []string {
	var cols []string
	for _, part := range strings.Split(line, "  ") {
		if part = strings.TrimSpace(part); part != "" {
			cols = append(cols, part)
		}
	}
	return cols
}
