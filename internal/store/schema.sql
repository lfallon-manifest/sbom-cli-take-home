-- Idempotent schema for the SBOM store. Executed statement-by-statement on every Open.
-- See DESIGN.md for the reasoning behind each table.

CREATE SEQUENCE IF NOT EXISTS seq_documents  START 1;
CREATE SEQUENCE IF NOT EXISTS seq_packages   START 1;
CREATE SEQUENCE IF NOT EXISTS seq_components START 1;
CREATE SEQUENCE IF NOT EXISTS seq_licenses   START 1;

-- One row per ingested SBOM.
-- document_key = 'serial:<serialNumber>@<version>' when a serialNumber is present, else
-- 'sha256:<content_hash>'. Byte-identical re-ingest is a no-op. A serial-numbered revision
-- is a new row with a higher version. content_hash is always stored.
CREATE TABLE IF NOT EXISTS documents (
  id            INTEGER   PRIMARY KEY DEFAULT nextval('seq_documents'),
  document_key  VARCHAR   NOT NULL UNIQUE,
  serial_number VARCHAR,
  version       INTEGER   NOT NULL DEFAULT 1,
  spec_version  VARCHAR,
  document_name VARCHAR,
  source_path   VARCHAR,
  content_hash  VARCHAR   NOT NULL,
  ingested_at   TIMESTAMP NOT NULL DEFAULT current_timestamp
);

-- Canonical package-version identity, shared across documents.
-- package_key is derived at ingest (see internal/normalize) because purl is optional.
CREATE TABLE IF NOT EXISTS packages (
  id            INTEGER   PRIMARY KEY DEFAULT nextval('seq_packages'),
  package_key   VARCHAR   NOT NULL UNIQUE,
  purl          VARCHAR,
  type          VARCHAR,
  group_name    VARCHAR,
  name          VARCHAR   NOT NULL,
  version       VARCHAR,
  first_seen_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);

-- One occurrence of a package inside one document. metadata.component is stored here
-- too, with is_primary = true, so dependency edges rooted at it do not dangle.
-- parent_component_id is intentionally not a declared FK: DuckDB's FK support is limited
-- and a self-referencing constraint buys nothing here.
CREATE TABLE IF NOT EXISTS components (
  id                  INTEGER PRIMARY KEY DEFAULT nextval('seq_components'),
  document_id         INTEGER NOT NULL REFERENCES documents(id),
  package_id          INTEGER NOT NULL REFERENCES packages(id),
  parent_component_id INTEGER,
  bom_ref             VARCHAR NOT NULL,
  is_primary          BOOLEAN NOT NULL DEFAULT false,
  UNIQUE (document_id, bom_ref)
);

-- license_key is a single derived non-null column ('spdx:mit' or 'name:<lowercased name>')
-- so UNIQUE actually deduplicates. NULLs are distinct under UNIQUE in SQL.
CREATE TABLE IF NOT EXISTS licenses (
  id          INTEGER PRIMARY KEY DEFAULT nextval('seq_licenses'),
  license_key VARCHAR NOT NULL UNIQUE,
  spdx_id     VARCHAR,
  name        VARCHAR
);

-- How one component declared its license(s). An expression like "MIT OR Apache-2.0"
-- becomes one row per extracted SPDX id, with the original expression preserved.
-- declared_source is one of: 'id', 'name', 'expression'.
CREATE TABLE IF NOT EXISTS component_licenses (
  component_id    INTEGER NOT NULL REFERENCES components(id),
  license_id      INTEGER NOT NULL REFERENCES licenses(id),
  raw_expression  VARCHAR,
  declared_source VARCHAR NOT NULL,
  PRIMARY KEY (component_id, license_id)
);

-- Per-document dependency edges: from_component depends on to_component.
CREATE TABLE IF NOT EXISTS dependencies (
  document_id       INTEGER NOT NULL REFERENCES documents(id),
  from_component_id INTEGER NOT NULL REFERENCES components(id),
  to_component_id   INTEGER NOT NULL REFERENCES components(id),
  PRIMARY KEY (document_id, from_component_id, to_component_id)
);

CREATE INDEX IF NOT EXISTS idx_packages_name          ON packages(name);
CREATE INDEX IF NOT EXISTS idx_components_package     ON components(package_id);
CREATE INDEX IF NOT EXISTS idx_components_document    ON components(document_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_to        ON dependencies(to_component_id);
CREATE INDEX IF NOT EXISTS idx_component_licenses_lic ON component_licenses(license_id);

-- Latest revision per serial number. Documents without a serial number are always "latest".
CREATE OR REPLACE VIEW latest_documents AS
  SELECT * FROM documents d
  WHERE d.serial_number IS NULL
     OR d.version = (
       SELECT MAX(version) FROM documents
       WHERE serial_number = d.serial_number
     );
