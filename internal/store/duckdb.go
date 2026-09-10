package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"

	_ "github.com/marcboeker/go-duckdb/v2"
)

//go:embed schema.sql
var schemaSQL string

// DuckStore is the DuckDB-backed Store. Ingest lives in ingest.go, queries in query.go.
type DuckStore struct {
	db *sql.DB
}

var _ Store = (*DuckStore)(nil)

// Open opens (creating if needed) the DuckDB database at path and applies the schema.
// An empty path opens an in-memory database, which is what tests use.
func Open(ctx context.Context, path string) (*DuckStore, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, fmt.Errorf("open duckdb %q: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect duckdb %q: %w", path, err)
	}
	s := &DuckStore{db: db}
	if err := s.initSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// initSchema runs each statement in schema.sql. All statements are idempotent.
func (s *DuckStore) initSchema(ctx context.Context) error {
	for stmt := range strings.SplitSeq(stripSQLComments(schemaSQL), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("init schema: %w\nstatement:\n%s", err, stmt)
		}
	}
	return nil
}

// stripSQLComments drops "--" line comments so a semicolon inside a comment is not
// mistaken for a statement boundary. The schema never uses string literals with "--".
func stripSQLComments(sqlText string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(sqlText, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// Close releases the underlying database handle.
func (s *DuckStore) Close() error {
	return s.db.Close()
}
