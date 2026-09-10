package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/lfallon/sbom-cli/internal/normalize"
)

// Ingest parses the CycloneDX JSON SBOM at path and stores it in one transaction.
// A document whose key is already stored is left untouched and reported as
// AlreadyPresent. Nothing is written if parsing or any insert fails.
func (s *DuckStore) Ingest(ctx context.Context, path string) (IngestResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return IngestResult{}, fmt.Errorf("read %s: %w", path, err)
	}
	bom, err := decodeBOM(path, data)
	if err != nil {
		return IngestResult{}, err
	}
	doc := describeDocument(path, data, bom)

	if existingID, found, err := s.findDocument(ctx, doc.key); err != nil {
		return IngestResult{}, err
	} else if found {
		return s.alreadyPresent(ctx, existingID, doc)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IngestResult{}, fmt.Errorf("begin ingest: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	ing, err := newIngester(ctx, tx)
	if err != nil {
		return IngestResult{}, err
	}
	defer ing.close()

	res, err := ing.run(bom, doc)
	if err != nil {
		return IngestResult{}, fmt.Errorf("ingest %s: %w", path, err)
	}
	if err := tx.Commit(); err != nil {
		return IngestResult{}, fmt.Errorf("commit ingest %s: %w", path, err)
	}
	return res, nil
}

// document is the identity and metadata of one SBOM, derived before any write.
type document struct {
	key         string
	serial      string
	version     int
	specVersion string
	name        string
	sourcePath  string
	contentHash string
}

func decodeBOM(path string, data []byte) (*cdx.BOM, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if bom.BOMFormat != "" && bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("parse %s: bomFormat is %q, expected \"CycloneDX\"", path, bom.BOMFormat)
	}
	return &bom, nil
}

// describeDocument derives the document key. A serial number keys the document
// as serial@version so revisions do not collide; otherwise the content hash does.
func describeDocument(path string, data []byte, bom *cdx.BOM) document {
	sum := sha256.Sum256(data)
	doc := document{
		serial:      bom.SerialNumber,
		version:     bom.Version,
		name:        filepath.Base(path),
		sourcePath:  path,
		contentHash: hex.EncodeToString(sum[:]),
	}
	if doc.version == 0 {
		doc.version = 1
	}
	if bom.SpecVersion > 0 {
		doc.specVersion = bom.SpecVersion.String()
	}
	if primary := primaryComponent(bom); primary != nil && primary.Name != "" {
		doc.name = primary.Name
	}
	if doc.serial != "" {
		doc.key = fmt.Sprintf("serial:%s@%d", doc.serial, doc.version)
	} else {
		doc.key = "sha256:" + doc.contentHash
	}
	return doc
}

func primaryComponent(bom *cdx.BOM) *cdx.Component {
	if bom.Metadata == nil {
		return nil
	}
	return bom.Metadata.Component
}

func (s *DuckStore) findDocument(ctx context.Context, key string) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM documents WHERE document_key = ?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("look up document %q: %w", key, err)
	}
	return id, true, nil
}

func (s *DuckStore) alreadyPresent(ctx context.Context, docID int64, doc document) (IngestResult, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM components WHERE document_id = ?`, docID).Scan(&count)
	if err != nil {
		return IngestResult{}, fmt.Errorf("count components for document %d: %w", docID, err)
	}
	return IngestResult{
		SerialNumber:   doc.serial,
		Version:        doc.version,
		DocumentName:   doc.name,
		Components:     count,
		AlreadyPresent: true,
	}, nil
}

// ingester holds the per-ingest transaction, prepared statements, id caches,
// and counters. One ingester handles exactly one document.
type ingester struct {
	ctx context.Context
	tx  *sql.Tx

	stmtComponent  *sql.Stmt
	stmtCompLic    *sql.Stmt
	stmtDependency *sql.Stmt

	docID        int64
	packageIDs   map[string]int64 // package_key -> packages.id
	licenseIDs   map[string]int64 // license_key -> licenses.id
	componentIDs map[string]int64 // bom_ref -> components.id
	syntheticN   int

	result IngestResult
}

func newIngester(ctx context.Context, tx *sql.Tx) (*ingester, error) {
	g := &ingester{
		ctx:          ctx,
		tx:           tx,
		packageIDs:   make(map[string]int64),
		licenseIDs:   make(map[string]int64),
		componentIDs: make(map[string]int64),
	}
	var err error
	if g.stmtComponent, err = tx.PrepareContext(ctx, `
		INSERT INTO components (document_id, package_id, parent_component_id, bom_ref, is_primary)
		VALUES (?, ?, ?, ?, ?) RETURNING id`); err != nil {
		return nil, fmt.Errorf("prepare component insert: %w", err)
	}
	if g.stmtCompLic, err = tx.PrepareContext(ctx, `
		INSERT INTO component_licenses (component_id, license_id, raw_expression, declared_source)
		VALUES (?, ?, ?, ?)`); err != nil {
		g.close()
		return nil, fmt.Errorf("prepare component_licenses insert: %w", err)
	}
	if g.stmtDependency, err = tx.PrepareContext(ctx, `
		INSERT INTO dependencies (document_id, from_component_id, to_component_id)
		VALUES (?, ?, ?)`); err != nil {
		g.close()
		return nil, fmt.Errorf("prepare dependencies insert: %w", err)
	}
	return g, nil
}

func (g *ingester) close() {
	for _, st := range []*sql.Stmt{g.stmtComponent, g.stmtCompLic, g.stmtDependency} {
		if st != nil {
			st.Close()
		}
	}
}

func (g *ingester) run(bom *cdx.BOM, doc document) (IngestResult, error) {
	g.result = IngestResult{SerialNumber: doc.serial, Version: doc.version, DocumentName: doc.name}
	if err := g.insertDocument(doc); err != nil {
		return IngestResult{}, err
	}
	if primary := primaryComponent(bom); primary != nil {
		if _, err := g.insertComponent(primary, sql.NullInt64{}, true); err != nil {
			return IngestResult{}, err
		}
	}
	if bom.Components != nil {
		if err := g.insertComponentTree(*bom.Components, sql.NullInt64{}); err != nil {
			return IngestResult{}, err
		}
	}
	if err := g.insertDependencies(bom.Dependencies); err != nil {
		return IngestResult{}, err
	}
	return g.result, nil
}

func (g *ingester) insertDocument(doc document) error {
	err := g.tx.QueryRowContext(g.ctx, `
		INSERT INTO documents (document_key, serial_number, version, spec_version, document_name, source_path, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		doc.key, nullString(doc.serial), doc.version, nullString(doc.specVersion),
		doc.name, doc.sourcePath, doc.contentHash,
	).Scan(&g.docID)
	if err != nil {
		return fmt.Errorf("insert document %q: %w", doc.key, err)
	}
	return nil
}

// insertComponentTree inserts each component and recurses into its nested
// components, recording the parent link.
func (g *ingester) insertComponentTree(comps []cdx.Component, parentID sql.NullInt64) error {
	for i := range comps {
		c := &comps[i]
		id, err := g.insertComponent(c, parentID, false)
		if err != nil {
			return err
		}
		if c.Components == nil {
			continue
		}
		childParent := sql.NullInt64{Int64: id, Valid: true}
		if err := g.insertComponentTree(*c.Components, childParent); err != nil {
			return err
		}
	}
	return nil
}

func (g *ingester) insertComponent(c *cdx.Component, parentID sql.NullInt64, primary bool) (int64, error) {
	bomRef := g.bomRefFor(c)
	if _, dup := g.componentIDs[bomRef]; dup {
		return 0, fmt.Errorf("duplicate bom-ref %q", bomRef)
	}
	pkgID, err := g.upsertPackage(c, bomRef)
	if err != nil {
		return 0, err
	}
	var id int64
	err = g.stmtComponent.QueryRowContext(g.ctx, g.docID, pkgID, parentID, bomRef, primary).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert component %q: %w", bomRef, err)
	}
	g.componentIDs[bomRef] = id
	g.result.Components++
	if err := g.insertLicenses(id, c.Licenses); err != nil {
		return 0, err
	}
	return id, nil
}

func (g *ingester) bomRefFor(c *cdx.Component) string {
	if c.BOMRef != "" {
		return c.BOMRef
	}
	g.syntheticN++
	return fmt.Sprintf("synthetic:%d", g.syntheticN)
}

// upsertPackage returns the packages.id for the component's package_key,
// inserting the row on first sight.
func (g *ingester) upsertPackage(c *cdx.Component, fallbackName string) (int64, error) {
	key := normalize.PackageKey(c.PackageURL, c.Group, c.Name, c.Version)
	if id, ok := g.packageIDs[key]; ok {
		return id, nil
	}
	id, found, err := g.selectID(`SELECT id FROM packages WHERE package_key = ?`, key)
	if err != nil {
		return 0, fmt.Errorf("look up package %q: %w", key, err)
	}
	if !found {
		name := c.Name
		if name == "" {
			name = fallbackName
		}
		err = g.tx.QueryRowContext(g.ctx, `
			INSERT INTO packages (package_key, purl, type, group_name, name, version)
			VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
			key, nullString(c.PackageURL), nullString(normalize.PurlType(c.PackageURL)),
			nullString(c.Group), name, nullString(c.Version),
		).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("insert package %q: %w", key, err)
		}
		g.result.NewPackages++
	}
	g.packageIDs[key] = id
	return id, nil
}

// declaredLicense is one (license, how it was declared) pair extracted from a
// component's licenses array.
type declaredLicense struct {
	key    string
	spdxID string
	name   string
	source string
	raw    string
}

func (g *ingester) insertLicenses(componentID int64, licenses *cdx.Licenses) error {
	if licenses == nil {
		return nil
	}
	seen := make(map[int64]bool)
	for _, choice := range *licenses {
		for _, dl := range extractLicenses(choice) {
			licID, err := g.upsertLicense(dl)
			if err != nil {
				return err
			}
			if seen[licID] {
				continue
			}
			seen[licID] = true
			_, err = g.stmtCompLic.ExecContext(g.ctx, componentID, licID, nullString(dl.raw), dl.source)
			if err != nil {
				return fmt.Errorf("insert component_license %q: %w", dl.key, err)
			}
		}
	}
	return nil
}

// extractLicenses flattens one CycloneDX license choice: an expression yields
// one entry per SPDX token; a license object yields one entry by id or name.
func extractLicenses(choice cdx.LicenseChoice) []declaredLicense {
	if choice.Expression != "" {
		tokens := normalize.LicenseTokens(choice.Expression)
		out := make([]declaredLicense, 0, len(tokens))
		for _, tok := range tokens {
			out = append(out, declaredLicense{
				key: normalize.LicenseKey(tok, ""), spdxID: tok, source: "expression", raw: choice.Expression,
			})
		}
		return out
	}
	lic := choice.License
	switch {
	case lic == nil:
		return nil
	case lic.ID != "":
		return []declaredLicense{{key: normalize.LicenseKey(lic.ID, ""), spdxID: lic.ID, source: "id"}}
	case lic.Name != "":
		return []declaredLicense{{key: normalize.LicenseKey("", lic.Name), name: lic.Name, source: "name"}}
	}
	return nil
}

func (g *ingester) upsertLicense(dl declaredLicense) (int64, error) {
	if id, ok := g.licenseIDs[dl.key]; ok {
		return id, nil
	}
	id, found, err := g.selectID(`SELECT id FROM licenses WHERE license_key = ?`, dl.key)
	if err != nil {
		return 0, fmt.Errorf("look up license %q: %w", dl.key, err)
	}
	if !found {
		err = g.tx.QueryRowContext(g.ctx, `
			INSERT INTO licenses (license_key, spdx_id, name) VALUES (?, ?, ?) RETURNING id`,
			dl.key, nullString(dl.spdxID), nullString(dl.name),
		).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("insert license %q: %w", dl.key, err)
		}
	}
	g.licenseIDs[dl.key] = id
	return id, nil
}

type edge struct{ from, to int64 }

// insertDependencies stores each dependsOn edge whose endpoints both resolve to
// a component in this document. Unresolvable endpoints are counted, not fatal.
func (g *ingester) insertDependencies(deps *[]cdx.Dependency) error {
	if deps == nil {
		return nil
	}
	seen := make(map[edge]bool)
	for _, d := range *deps {
		if d.Dependencies == nil {
			continue
		}
		fromID, fromOK := g.componentIDs[d.Ref]
		for _, target := range *d.Dependencies {
			toID, toOK := g.componentIDs[target]
			if !fromOK || !toOK {
				g.result.DanglingRefs++
				continue
			}
			e := edge{fromID, toID}
			if seen[e] {
				continue
			}
			seen[e] = true
			if _, err := g.stmtDependency.ExecContext(g.ctx, g.docID, fromID, toID); err != nil {
				return fmt.Errorf("insert dependency %q -> %q: %w", d.Ref, target, err)
			}
			g.result.Dependencies++
		}
	}
	return nil
}

func (g *ingester) selectID(query string, arg any) (int64, bool, error) {
	var id int64
	err := g.tx.QueryRowContext(g.ctx, query, arg).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
