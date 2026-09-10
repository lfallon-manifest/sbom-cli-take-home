package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	minimalFixture   = "testdata/minimal.cdx.json"
	malformedFixture = "testdata/malformed.json"
	minimalSerial    = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
	// primary + express, body-parser, qs, internal-lib, no-ref-lib, outer, inner
	minimalComponents = 8
)

func openTestStore(t *testing.T) *DuckStore {
	t.Helper()
	s, err := Open(context.Background(), "")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func queryInt(t *testing.T, s *DuckStore, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func queryString(t *testing.T, s *DuckStore, query string, args ...any) string {
	t.Helper()
	var v string
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&v); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return v
}

func TestIngestCountsRows(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	res, err := s.Ingest(ctx, minimalFixture)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if res.AlreadyPresent {
		t.Error("AlreadyPresent = true on first ingest")
	}
	if res.SerialNumber != minimalSerial {
		t.Errorf("SerialNumber = %q, want %q", res.SerialNumber, minimalSerial)
	}
	if res.Version != 1 {
		t.Errorf("Version = %d, want 1", res.Version)
	}
	if res.DocumentName != "app" {
		t.Errorf("DocumentName = %q, want %q", res.DocumentName, "app")
	}
	if res.Components != minimalComponents {
		t.Errorf("Components = %d, want %d", res.Components, minimalComponents)
	}
	if res.NewPackages != minimalComponents {
		t.Errorf("NewPackages = %d, want %d", res.NewPackages, minimalComponents)
	}
	if res.Dependencies != 3 {
		t.Errorf("Dependencies = %d, want 3", res.Dependencies)
	}
	if res.DanglingRefs != 1 {
		t.Errorf("DanglingRefs = %d, want 1", res.DanglingRefs)
	}

	t.Run("document row", func(t *testing.T) {
		wantKey := "serial:" + minimalSerial + "@1"
		if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 1 {
			t.Errorf("documents count = %d, want 1", n)
		}
		if n := queryInt(t, s, `SELECT count(*) FROM documents WHERE document_key = ?`, wantKey); n != 1 {
			t.Errorf("documents with key %q = %d, want 1", wantKey, n)
		}
		if got := queryString(t, s, `SELECT spec_version FROM documents`); got != "1.6" {
			t.Errorf("spec_version = %q, want 1.6", got)
		}
	})

	t.Run("primary component", func(t *testing.T) {
		n := queryInt(t, s, `SELECT count(*) FROM components WHERE is_primary AND bom_ref = 'app'`)
		if n != 1 {
			t.Errorf("primary components = %d, want 1", n)
		}
		if total := queryInt(t, s, `SELECT count(*) FROM components WHERE is_primary`); total != 1 {
			t.Errorf("total is_primary rows = %d, want 1", total)
		}
	})

	t.Run("package keys", func(t *testing.T) {
		got := queryString(t, s, `SELECT package_key FROM packages WHERE name = 'qs'`)
		if got != "pkg:npm/qs@6.11.0" {
			t.Errorf("qs package_key = %q, want pkg:npm/qs@6.11.0", got)
		}
		if purl := queryString(t, s, `SELECT purl FROM packages WHERE name = 'qs'`); purl != "pkg:NPM/qs@6.11.0?foo=bar#sub" {
			t.Errorf("qs raw purl = %q, want original string", purl)
		}
		if typ := queryString(t, s, `SELECT type FROM packages WHERE name = 'qs'`); typ != "npm" {
			t.Errorf("qs type = %q, want npm", typ)
		}
		got = queryString(t, s, `SELECT package_key FROM packages WHERE name = 'internal-lib'`)
		if got != "generic:internal-lib@0.1.0" {
			t.Errorf("internal-lib package_key = %q, want generic:internal-lib@0.1.0", got)
		}
		n := queryInt(t, s, `SELECT count(*) FROM packages WHERE name = 'internal-lib' AND purl IS NULL AND type IS NULL`)
		if n != 1 {
			t.Errorf("internal-lib rows with NULL purl and type = %d, want 1", n)
		}
	})

	t.Run("expression licenses", func(t *testing.T) {
		const q = `
			SELECT count(*) FROM component_licenses cl
			JOIN components c ON c.id = cl.component_id
			JOIN licenses l ON l.id = cl.license_id
			WHERE c.bom_ref = 'pkg:npm/body-parser@1.20.2'
			  AND l.license_key = ?
			  AND cl.raw_expression = 'MIT OR Apache-2.0'
			  AND cl.declared_source = 'expression'`
		for _, key := range []string{"spdx:mit", "spdx:apache-2.0"} {
			if n := queryInt(t, s, q, key); n != 1 {
				t.Errorf("body-parser rows for %s = %d, want 1", key, n)
			}
		}
		total := queryInt(t, s, `
			SELECT count(*) FROM component_licenses cl
			JOIN components c ON c.id = cl.component_id
			WHERE c.bom_ref = 'pkg:npm/body-parser@1.20.2'`)
		if total != 2 {
			t.Errorf("body-parser component_licenses = %d, want 2", total)
		}
	})

	t.Run("id license", func(t *testing.T) {
		n := queryInt(t, s, `
			SELECT count(*) FROM component_licenses cl
			JOIN components c ON c.id = cl.component_id
			JOIN licenses l ON l.id = cl.license_id
			WHERE c.bom_ref = 'pkg:npm/express@4.18.2'
			  AND l.license_key = 'spdx:mit' AND l.spdx_id = 'MIT'
			  AND cl.declared_source = 'id' AND cl.raw_expression IS NULL`)
		if n != 1 {
			t.Errorf("express MIT rows = %d, want 1", n)
		}
		if n := queryInt(t, s, `SELECT count(*) FROM licenses WHERE license_key = 'spdx:mit'`); n != 1 {
			t.Errorf("spdx:mit license rows = %d, want 1 (shared between express and body-parser)", n)
		}
	})

	t.Run("named license", func(t *testing.T) {
		n := queryInt(t, s, `
			SELECT count(*) FROM licenses
			WHERE license_key = 'name:custom license' AND name = 'Custom License' AND spdx_id IS NULL`)
		if n != 1 {
			t.Errorf("custom license rows = %d, want 1", n)
		}
		n = queryInt(t, s, `
			SELECT count(*) FROM component_licenses cl
			JOIN components c ON c.id = cl.component_id
			WHERE c.bom_ref = 'internal-lib' AND cl.declared_source = 'name'`)
		if n != 1 {
			t.Errorf("internal-lib component_licenses = %d, want 1", n)
		}
	})

	t.Run("nested component", func(t *testing.T) {
		n := queryInt(t, s, `
			SELECT count(*) FROM components child
			JOIN components parent ON parent.id = child.parent_component_id
			WHERE child.bom_ref = 'pkg:npm/inner@1.0.0' AND parent.bom_ref = 'pkg:npm/outer@1.0.0'`)
		if n != 1 {
			t.Errorf("inner rows parented by outer = %d, want 1", n)
		}
		if n := queryInt(t, s, `SELECT count(*) FROM components WHERE parent_component_id IS NOT NULL`); n != 1 {
			t.Errorf("components with a parent = %d, want 1", n)
		}
	})

	t.Run("synthetic bom-ref", func(t *testing.T) {
		got := queryString(t, s, `
			SELECT c.bom_ref FROM components c
			JOIN packages p ON p.id = c.package_id
			WHERE p.name = 'no-ref-lib'`)
		if !strings.HasPrefix(got, "synthetic:") {
			t.Errorf("no-ref-lib bom_ref = %q, want synthetic: prefix", got)
		}
	})

	t.Run("dependency edges", func(t *testing.T) {
		if n := queryInt(t, s, `SELECT count(*) FROM dependencies`); n != 3 {
			t.Errorf("dependencies rows = %d, want 3", n)
		}
		n := queryInt(t, s, `
			SELECT count(*) FROM dependencies d
			JOIN components f ON f.id = d.from_component_id
			JOIN components t ON t.id = d.to_component_id
			WHERE f.bom_ref = 'app' AND t.bom_ref = 'pkg:npm/express@4.18.2'`)
		if n != 1 {
			t.Errorf("app -> express edges = %d, want 1", n)
		}
	})
}

func TestIngestIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first, err := s.Ingest(ctx, minimalFixture)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	second, err := s.Ingest(ctx, minimalFixture)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	if !second.AlreadyPresent {
		t.Error("second ingest AlreadyPresent = false, want true")
	}
	if second.Components != first.Components {
		t.Errorf("second Components = %d, want %d", second.Components, first.Components)
	}
	if second.SerialNumber != minimalSerial || second.Version != 1 || second.DocumentName != "app" {
		t.Errorf("second result identity = %+v, want serial/version/name of the stored document", second)
	}
	if second.NewPackages != 0 || second.Dependencies != 0 {
		t.Errorf("second ingest reported writes: %+v", second)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 1 {
		t.Errorf("documents = %d, want 1", n)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM components`); n != minimalComponents {
		t.Errorf("components = %d, want %d", n, minimalComponents)
	}
}

func TestIngestMalformedFailsCleanly(t *testing.T) {
	s := openTestStore(t)

	_, err := s.Ingest(context.Background(), malformedFixture)
	if err == nil {
		t.Fatal("ingest of malformed JSON returned nil error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error = %q, want it to mention parse", err)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 0 {
		t.Errorf("documents after failed ingest = %d, want 0", n)
	}
}

func TestIngestRejectsWrongBOMFormat(t *testing.T) {
	s := openTestStore(t)
	path := writeFixture(t, `{"bomFormat": "SPDX", "specVersion": "1.6", "version": 1}`)

	_, err := s.Ingest(context.Background(), path)
	if err == nil {
		t.Fatal("ingest of non-CycloneDX bomFormat returned nil error")
	}
	if !strings.Contains(err.Error(), "bomFormat") {
		t.Errorf("error = %q, want it to mention bomFormat", err)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 0 {
		t.Errorf("documents after rejected ingest = %d, want 0", n)
	}
}

func TestIngestRejectsDuplicateBOMRef(t *testing.T) {
	s := openTestStore(t)
	path := writeFixture(t, `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
	  "components": [
	    {"bom-ref": "dup", "type": "library", "name": "a", "version": "1"},
	    {"bom-ref": "dup", "type": "library", "name": "b", "version": "2"}
	  ]
	}`)

	_, err := s.Ingest(context.Background(), path)
	if err == nil {
		t.Fatal("ingest with duplicate bom-ref returned nil error")
	}
	if !strings.Contains(err.Error(), `duplicate bom-ref "dup"`) {
		t.Errorf("error = %q, want duplicate bom-ref message", err)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 0 {
		t.Errorf("documents after failed ingest = %d, want 0 (transaction rolled back)", n)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM packages`); n != 0 {
		t.Errorf("packages after failed ingest = %d, want 0 (transaction rolled back)", n)
	}
}

func TestIngestWithoutSerialKeysOnHash(t *testing.T) {
	s := openTestStore(t)
	path := writeFixture(t, `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
	  "components": [{"bom-ref": "a", "type": "library", "name": "a", "version": "1"}]
	}`)

	res, err := s.Ingest(context.Background(), path)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.DocumentName != filepath.Base(path) {
		t.Errorf("DocumentName = %q, want file base name %q", res.DocumentName, filepath.Base(path))
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents WHERE document_key LIKE 'sha256:%' AND serial_number IS NULL`); n != 1 {
		t.Errorf("hash-keyed documents = %d, want 1", n)
	}
}

func TestIngestSharesPackagesAcrossDocuments(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.Ingest(ctx, minimalFixture); err != nil {
		t.Fatalf("ingest minimal: %v", err)
	}
	second := writeFixture(t, `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
	  "version": 1,
	  "metadata": {"component": {"bom-ref": "other-app", "type": "application", "name": "other-app", "version": "2.0.0"}},
	  "components": [
	    {"bom-ref": "pkg:npm/express@4.18.2", "type": "library", "name": "express", "version": "4.18.2",
	     "purl": "pkg:npm/express@4.18.2", "licenses": [{"license": {"id": "MIT"}}]},
	    {"bom-ref": "pkg:npm/brand-new@1.0.0", "type": "library", "name": "brand-new", "version": "1.0.0",
	     "purl": "pkg:npm/brand-new@1.0.0"}
	  ],
	  "dependencies": [{"ref": "other-app", "dependsOn": ["pkg:npm/express@4.18.2", "pkg:npm/brand-new@1.0.0"]}]
	}`)

	res, err := s.Ingest(ctx, second)
	if err != nil {
		t.Fatalf("ingest second: %v", err)
	}
	if res.AlreadyPresent {
		t.Error("second document reported AlreadyPresent")
	}
	if res.Components != 3 {
		t.Errorf("Components = %d, want 3", res.Components)
	}
	// other-app and brand-new are new; express is shared with the first document.
	if res.NewPackages != 2 {
		t.Errorf("NewPackages = %d, want 2", res.NewPackages)
	}
	if res.Dependencies != 2 {
		t.Errorf("Dependencies = %d, want 2", res.Dependencies)
	}

	const key = "pkg:npm/express@4.18.2"
	if n := queryInt(t, s, `SELECT count(*) FROM packages WHERE package_key = ?`, key); n != 1 {
		t.Errorf("packages with key %s = %d, want 1", key, n)
	}
	n := queryInt(t, s, `
		SELECT count(*) FROM components c JOIN packages p ON p.id = c.package_id
		WHERE p.package_key = ?`, key)
	if n != 2 {
		t.Errorf("components referencing %s = %d, want 2", key, n)
	}
	if n := queryInt(t, s, `SELECT count(*) FROM documents`); n != 2 {
		t.Errorf("documents = %d, want 2", n)
	}
}

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.cdx.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
