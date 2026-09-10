package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefusesNonEmptyOutputDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep-me.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed dir: %v", err)
	}

	err := run([]string{"--out", dir, "--documents", "1", "--components", "5"}, io.Discard)
	if err == nil {
		t.Fatal("run succeeded against a non-empty directory, want refusal")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error %q does not point at --force", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keep-me.json")); err != nil {
		t.Errorf("pre-existing file was disturbed: %v", err)
	}
}

func TestWritesManifestAlongsideCorpus(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "corpus")

	if err := run([]string{"--out", dir, "--documents", "3", "--components", "10", "--seed", "5"}, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.Summary.Documents != 3 {
		t.Errorf("manifest documents = %d, want 3", m.Summary.Documents)
	}
	if m.Config.Seed != 5 {
		t.Errorf("manifest seed = %d, want 5", m.Config.Seed)
	}
	if len(m.Summary.TopPackages) == 0 {
		t.Error("manifest carries no top packages to query")
	}
	// The manifest is not an SBOM and must not be picked up by an ingest glob.
	files, err := filepath.Glob(filepath.Join(dir, "*.cdx.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("glob matched %d files, want the 3 SBOMs: %v", len(files), files)
	}
}
