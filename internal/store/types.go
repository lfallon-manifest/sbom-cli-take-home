package store

import "context"

// Store is the contract between the CLI layer and the DuckDB-backed implementation.
type Store interface {
	Ingest(ctx context.Context, path string) (IngestResult, error)
	QueryByComponent(ctx context.Context, name, version string) ([]ComponentHit, error)
	QueryByLicense(ctx context.Context, license string) ([]LicenseHit, error)
	Close() error
}

// IngestResult summarizes what one ingest run did, for CLI feedback.
type IngestResult struct {
	SerialNumber   string `json:"serialNumber"`
	Version        int    `json:"version"`
	DocumentName   string `json:"documentName"`
	Components     int    `json:"components"`
	NewPackages    int    `json:"newPackages"`
	Dependencies   int    `json:"dependencies"`
	DanglingRefs   int    `json:"danglingRefs"`
	AlreadyPresent bool   `json:"alreadyPresent"`
}

// ComponentHit is one component matching a --component query, in one document.
type ComponentHit struct {
	DocumentSerial   string `json:"documentSerial"`
	DocumentVersion  int    `json:"documentVersion"`
	DocumentName     string `json:"documentName"`
	ComponentName    string `json:"componentName"`
	ComponentVersion string `json:"componentVersion"`
	PackageKey       string `json:"packageKey"`
	Purl             string `json:"purl,omitempty"`
	// Dependents are the transitive ancestors that depend on this component,
	// rendered as "name@version", nearest first.
	Dependents []string `json:"dependents,omitempty"`
}

// LicenseHit is one component matching a --license query, in one document.
type LicenseHit struct {
	DocumentSerial   string `json:"documentSerial"`
	DocumentVersion  int    `json:"documentVersion"`
	DocumentName     string `json:"documentName"`
	ComponentName    string `json:"componentName"`
	ComponentVersion string `json:"componentVersion"`
	MatchedLicense   string `json:"matchedLicense"`
	RawExpression    string `json:"rawExpression,omitempty"`
}
