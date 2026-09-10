package store

import (
	"context"
	"database/sql"
	"fmt"
)

// componentMatch is the shared predicate for --component: exact case-insensitive name,
// exact case-sensitive version when one is given. $1 is the name, $2 the version, and an
// empty version matches every version.
const componentMatch = `lower(p.name) = lower($1) AND ($2 = '' OR p.version = $2)`

const componentHitsSQL = `
SELECT c.id, d.serial_number, d.version, d.document_name,
       p.name, p.version, p.package_key, p.purl
FROM components c
JOIN packages  p ON p.id = c.package_id
JOIN documents d ON d.id = c.document_id
WHERE ` + componentMatch + `
ORDER BY d.document_name, d.version, p.name, p.version, c.id`

// dependentsSQL walks dependencies backwards from each matched component to every
// transitive ancestor in the same document. UNION dedupes rows so a cycle cannot keep
// re-emitting the same (target, ancestor, depth) tuple, and the depth cap bounds the walk
// even when a cycle keeps producing new depths. The matched component is excluded from its
// own ancestors because a cycle can lead back to it.
const dependentsSQL = `
WITH RECURSIVE matches AS (
  SELECT c.id AS component_id
  FROM components c JOIN packages p ON p.id = c.package_id
  WHERE ` + componentMatch + `
),
walk AS (
  SELECT m.component_id AS target_id, dep.from_component_id AS ancestor_id, 1 AS depth
  FROM matches m JOIN dependencies dep ON dep.to_component_id = m.component_id
  UNION
  SELECT w.target_id, dep.from_component_id, w.depth + 1
  FROM walk w JOIN dependencies dep ON dep.to_component_id = w.ancestor_id
  WHERE w.depth < 64
)
SELECT w.target_id, p.name, p.version
FROM walk w
JOIN components c ON c.id = w.ancestor_id
JOIN packages   p ON p.id = c.package_id
WHERE w.ancestor_id <> w.target_id
GROUP BY w.target_id, p.name, p.version
ORDER BY w.target_id, MIN(w.depth), p.name, p.version`

const licenseHitsSQL = `
SELECT d.serial_number, d.version, d.document_name,
       p.name, p.version, COALESCE(l.spdx_id, l.name), cl.raw_expression
FROM component_licenses cl
JOIN licenses   l ON l.id = cl.license_id
JOIN components c ON c.id = cl.component_id
JOIN packages   p ON p.id = c.package_id
JOIN documents  d ON d.id = c.document_id
WHERE l.license_key = 'spdx:' || lower($1)
   OR l.license_key = 'name:' || lower($1)
ORDER BY d.document_name, d.version, p.name, p.version, c.id, l.license_key`

// QueryByComponent finds components by exact case-insensitive name (and exact version if
// non-empty), returning the documents that contain them and their transitive dependents.
func (s *DuckStore) QueryByComponent(ctx context.Context, name, version string) ([]ComponentHit, error) {
	dependents, err := s.loadDependents(ctx, name, version)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, componentHitsSQL, name, version)
	if err != nil {
		return nil, fmt.Errorf("query by component: %w", err)
	}
	defer rows.Close()
	return scanComponentHits(rows, dependents)
}

// loadDependents returns each matched component's transitive dependents, keyed by
// component id and ordered nearest first.
func (s *DuckStore) loadDependents(ctx context.Context, name, version string) (map[int64][]string, error) {
	rows, err := s.db.QueryContext(ctx, dependentsSQL, name, version)
	if err != nil {
		return nil, fmt.Errorf("query dependents: %w", err)
	}
	defer rows.Close()

	out := map[int64][]string{}
	for rows.Next() {
		var target int64
		var depName string
		var depVersion sql.NullString
		if err := rows.Scan(&target, &depName, &depVersion); err != nil {
			return nil, fmt.Errorf("scan dependent: %w", err)
		}
		out[target] = append(out[target], componentRef(depName, depVersion.String))
	}
	return out, rows.Err()
}

func scanComponentHits(rows *sql.Rows, dependents map[int64][]string) ([]ComponentHit, error) {
	hits := []ComponentHit{}
	for rows.Next() {
		var id int64
		var serial, docName, compVersion, purl sql.NullString
		var h ComponentHit
		if err := rows.Scan(&id, &serial, &h.DocumentVersion, &docName,
			&h.ComponentName, &compVersion, &h.PackageKey, &purl); err != nil {
			return nil, fmt.Errorf("scan component hit: %w", err)
		}
		h.DocumentSerial = serial.String
		h.DocumentName = docName.String
		h.ComponentVersion = compVersion.String
		h.Purl = purl.String
		h.Dependents = dependents[id]
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// componentRef renders a component as name@version, or just name when version is empty.
func componentRef(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// QueryByLicense finds components declared under the given license, case-insensitive.
// It matches SPDX ids extracted from expressions and, as a convenience, name-only licenses.
func (s *DuckStore) QueryByLicense(ctx context.Context, license string) ([]LicenseHit, error) {
	rows, err := s.db.QueryContext(ctx, licenseHitsSQL, license)
	if err != nil {
		return nil, fmt.Errorf("query by license: %w", err)
	}
	defer rows.Close()
	return scanLicenseHits(rows)
}

func scanLicenseHits(rows *sql.Rows) ([]LicenseHit, error) {
	hits := []LicenseHit{}
	for rows.Next() {
		var serial, docName, compVersion, matched, raw sql.NullString
		var h LicenseHit
		if err := rows.Scan(&serial, &h.DocumentVersion, &docName,
			&h.ComponentName, &compVersion, &matched, &raw); err != nil {
			return nil, fmt.Errorf("scan license hit: %w", err)
		}
		h.DocumentSerial = serial.String
		h.DocumentName = docName.String
		h.ComponentVersion = compVersion.String
		h.MatchedLicense = matched.String
		h.RawExpression = raw.String
		hits = append(hits, h)
	}
	return hits, rows.Err()
}
