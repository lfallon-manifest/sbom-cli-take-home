package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

const webFrontendSerial = "urn:uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

// seedSQL builds three documents by hand with explicit ids so the queries can be tested
// without going through Ingest.
//
//	web-frontend (doc 1): app(1) -> express(2) -> body-parser(3) -> qs(4); app(1) -> lodash(5)
//	api-service  (doc 2): api(6) -> lodash(7); api(6) -> qs(8)   [qs shares package row 4]
//	cyclic       (doc 3): root(9) -> a(10) -> b(11) -> c(12) -> a(10)
var seedSQL = []string{
	`INSERT INTO documents (id, document_key, serial_number, version, document_name, content_hash) VALUES
	   (1, '` + webFrontendSerial + `', '` + webFrontendSerial + `', 1, 'web-frontend', 'h1'),
	   (2, 'sha256:h2', NULL, 1, 'api-service', 'h2'),
	   (3, 'sha256:h3', NULL, 1, 'cyclic', 'h3')`,

	`INSERT INTO packages (id, package_key, purl, type, name, version) VALUES
	   (1,  'generic:app@1.0.0',            NULL,                           NULL,  'app',         '1.0.0'),
	   (2,  'pkg:npm/express@4.18.2',       'pkg:npm/express@4.18.2',       'npm', 'express',     '4.18.2'),
	   (3,  'pkg:npm/body-parser@1.20.2',   'pkg:npm/body-parser@1.20.2',   'npm', 'body-parser', '1.20.2'),
	   (4,  'pkg:npm/qs@6.11.0',            'pkg:npm/qs@6.11.0',            'npm', 'qs',          '6.11.0'),
	   (5,  'pkg:npm/lodash@4.17.21',       'pkg:npm/lodash@4.17.21',       'npm', 'lodash',      '4.17.21'),
	   (6,  'generic:api@2.0.0',            NULL,                           NULL,  'api',         '2.0.0'),
	   (7,  'pkg:npm/lodash@4.17.15',       'pkg:npm/lodash@4.17.15',       'npm', 'lodash',      '4.17.15'),
	   (8,  'generic:root@1.0.0',           NULL,                           NULL,  'root',        '1.0.0'),
	   (9,  'generic:a@1',                  NULL,                           NULL,  'a',           '1'),
	   (10, 'generic:b@1',                  NULL,                           NULL,  'b',           '1'),
	   (11, 'generic:c@1',                  NULL,                           NULL,  'c',           '1')`,

	`INSERT INTO components (id, document_id, package_id, bom_ref, is_primary) VALUES
	   (1,  1, 1,  'app',         true),
	   (2,  1, 2,  'express',     false),
	   (3,  1, 3,  'body-parser', false),
	   (4,  1, 4,  'qs',          false),
	   (5,  1, 5,  'lodash',      false),
	   (6,  2, 6,  'api',         true),
	   (7,  2, 7,  'lodash',      false),
	   (8,  2, 4,  'qs',          false),
	   (9,  3, 8,  'root',        true),
	   (10, 3, 9,  'a',           false),
	   (11, 3, 10, 'b',           false),
	   (12, 3, 11, 'c',           false)`,

	`INSERT INTO dependencies (document_id, from_component_id, to_component_id) VALUES
	   (1, 1, 2), (1, 2, 3), (1, 3, 4), (1, 1, 5),
	   (2, 6, 7), (2, 6, 8),
	   (3, 9, 10), (3, 10, 11), (3, 11, 12), (3, 12, 10)`,

	`INSERT INTO licenses (id, license_key, spdx_id, name) VALUES
	   (1, 'spdx:mit',                        'MIT',        NULL),
	   (2, 'spdx:apache-2.0',                 'Apache-2.0', NULL),
	   (3, 'name:custom proprietary license', NULL,         'Custom Proprietary License')`,

	`INSERT INTO component_licenses (component_id, license_id, raw_expression, declared_source) VALUES
	   (2, 1, NULL,                 'id'),
	   (3, 1, 'MIT OR Apache-2.0',  'expression'),
	   (3, 2, 'MIT OR Apache-2.0',  'expression'),
	   (7, 3, NULL,                 'name')`,
}

func newSeededStore(t *testing.T) *DuckStore {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, "")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	for _, stmt := range seedSQL {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed: %v\n%s", err, stmt)
		}
	}
	return s
}

func requireNonNilEmpty[T any](t *testing.T, hits []T) {
	t.Helper()
	if hits == nil {
		t.Fatal("expected empty non-nil slice, got nil")
	}
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %d: %+v", len(hits), hits)
	}
}

func TestQueryByComponentAllVersions(t *testing.T) {
	s := newSeededStore(t)
	ctx := context.Background()

	for _, name := range []string{"lodash", "LODASH"} {
		hits, err := s.QueryByComponent(ctx, name, "")
		if err != nil {
			t.Fatalf("query %q: %v", name, err)
		}
		if len(hits) != 2 {
			t.Fatalf("query %q: expected 2 hits, got %d: %+v", name, len(hits), hits)
		}

		api, web := hits[0], hits[1]
		if api.DocumentName != "api-service" || api.ComponentVersion != "4.17.15" {
			t.Errorf("hit[0] = %+v, want api-service lodash 4.17.15", api)
		}
		if api.DocumentSerial != "" {
			t.Errorf("api-service serial = %q, want empty for NULL", api.DocumentSerial)
		}
		if web.DocumentName != "web-frontend" || web.ComponentVersion != "4.17.21" {
			t.Errorf("hit[1] = %+v, want web-frontend lodash 4.17.21", web)
		}
		if web.DocumentSerial != webFrontendSerial || web.DocumentVersion != 1 {
			t.Errorf("web-frontend serial/version = %q/%d", web.DocumentSerial, web.DocumentVersion)
		}
		if web.ComponentName != "lodash" || web.PackageKey != "pkg:npm/lodash@4.17.21" || web.Purl != "pkg:npm/lodash@4.17.21" {
			t.Errorf("web-frontend identity = %+v", web)
		}
	}
}

func TestQueryByComponentWithVersion(t *testing.T) {
	s := newSeededStore(t)
	ctx := context.Background()

	hits, err := s.QueryByComponent(ctx, "lodash", "4.17.15")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].DocumentName != "api-service" || hits[0].ComponentVersion != "4.17.15" {
		t.Errorf("hit = %+v, want api-service lodash 4.17.15", hits[0])
	}

	none, err := s.QueryByComponent(ctx, "lodash", "9.9.9")
	if err != nil {
		t.Fatalf("query unknown version: %v", err)
	}
	requireNonNilEmpty(t, none)
}

func TestQueryByComponentDependentsNearestFirst(t *testing.T) {
	s := newSeededStore(t)

	hits, err := s.QueryByComponent(context.Background(), "qs", "")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d: %+v", len(hits), hits)
	}

	byDoc := map[string][]string{}
	for _, h := range hits {
		byDoc[h.DocumentName] = h.Dependents
	}
	wantWeb := []string{"body-parser@1.20.2", "express@4.18.2", "app@1.0.0"}
	if got := byDoc["web-frontend"]; !slices.Equal(got, wantWeb) {
		t.Errorf("web-frontend dependents = %v, want %v", got, wantWeb)
	}
	wantAPI := []string{"api@2.0.0"}
	if got := byDoc["api-service"]; !slices.Equal(got, wantAPI) {
		t.Errorf("api-service dependents = %v, want %v", got, wantAPI)
	}
}

func TestQueryByComponentCycleTerminates(t *testing.T) {
	s := newSeededStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hits, err := s.QueryByComponent(ctx, "c", "")
	if ctx.Err() != nil {
		t.Fatalf("query did not terminate within timeout: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}

	want := []string{"b@1", "a@1", "root@1.0.0"}
	if got := hits[0].Dependents; !slices.Equal(got, want) {
		t.Errorf("dependents = %v, want %v", got, want)
	}
	if slices.Contains(hits[0].Dependents, "c@1") {
		t.Errorf("component must not be listed as its own dependent: %v", hits[0].Dependents)
	}
}

func TestQueryByComponentPurlNotSearched(t *testing.T) {
	s := newSeededStore(t)

	hits, err := s.QueryByComponent(context.Background(), "pkg:npm/lodash@4.17.21", "")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	requireNonNilEmpty(t, hits)
}

func TestQueryByLicenseMatchesExpressionTokens(t *testing.T) {
	s := newSeededStore(t)
	ctx := context.Background()

	mit, err := s.QueryByLicense(ctx, "MIT")
	if err != nil {
		t.Fatalf("query MIT: %v", err)
	}
	if len(mit) != 2 {
		t.Fatalf("MIT: expected 2 hits, got %d: %+v", len(mit), mit)
	}
	bodyParser, express := mit[0], mit[1]
	if bodyParser.ComponentName != "body-parser" || bodyParser.RawExpression != "MIT OR Apache-2.0" {
		t.Errorf("MIT hit[0] = %+v, want body-parser with raw expression", bodyParser)
	}
	if express.ComponentName != "express" || express.RawExpression != "" {
		t.Errorf("MIT hit[1] = %+v, want express with empty raw expression", express)
	}
	for _, h := range mit {
		if h.MatchedLicense != "MIT" || h.DocumentName != "web-frontend" || h.DocumentSerial != webFrontendSerial {
			t.Errorf("MIT hit = %+v", h)
		}
	}

	apache, err := s.QueryByLicense(ctx, "apache-2.0")
	if err != nil {
		t.Fatalf("query apache-2.0: %v", err)
	}
	if len(apache) != 1 || apache[0].ComponentName != "body-parser" || apache[0].MatchedLicense != "Apache-2.0" {
		t.Errorf("apache-2.0 hits = %+v, want body-parser only", apache)
	}

	gpl, err := s.QueryByLicense(ctx, "GPL-3.0-only")
	if err != nil {
		t.Fatalf("query GPL-3.0-only: %v", err)
	}
	requireNonNilEmpty(t, gpl)
}

func TestQueryByLicenseMatchesNameOnly(t *testing.T) {
	s := newSeededStore(t)

	hits, err := s.QueryByLicense(context.Background(), "Custom Proprietary License")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.DocumentName != "api-service" || h.ComponentName != "lodash" || h.ComponentVersion != "4.17.15" {
		t.Errorf("hit = %+v, want api-service lodash 4.17.15", h)
	}
	if h.MatchedLicense != "Custom Proprietary License" || h.RawExpression != "" {
		t.Errorf("hit license = %q / raw %q", h.MatchedLicense, h.RawExpression)
	}
}
