package corpus

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"
)

// Graph shape knobs. A document is a random recursive DAG rooted at the primary
// component: every component attaches to one earlier node, a quarter of them
// pick up a second parent, and edges always point from an earlier node to a
// later one so the graph stays acyclic unless a cycle is asked for.
const (
	directDependencyRate = 0.06
	crossEdgeRate        = 0.25
	hotDrawRate          = 0.70 // share of picks taken from the Zipf-hot head
	zipfExponent         = 1.15
)

// Distinct random streams, so changing one part of the corpus does not reshuffle another.
const (
	universeStream uint64 = 0x9E3779B97F4A7C15
	documentStream uint64 = 0xBF58476D1CE4E5B9
	revisionStream uint64 = 0x94D049BB133111EB
)

// revisionRoll decides whether document index gets a revision. It uses its own
// stream so the decision does not depend on how many draws building the
// document happened to consume.
func revisionRoll(cfg Config, index int) float64 {
	return rand.New(rand.NewPCG(uint64(cfg.Seed)^revisionStream, uint64(index))).Float64()
}

var corpusEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type dependencyJSON struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type toolsJSON struct {
	Components []componentJSON `json:"components"`
}

type metadataJSON struct {
	Timestamp string        `json:"timestamp"`
	Tools     toolsJSON     `json:"tools"`
	Component componentJSON `json:"component"`
}

type documentJSON struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber,omitempty"`
	Version      int               `json:"version"`
	Metadata     metadataJSON      `json:"metadata"`
	Components   []json.RawMessage `json:"components"`
	Dependencies []dependencyJSON  `json:"dependencies"`
}

// document is one generated SBOM plus the bookkeeping the summary needs.
type document struct {
	bom   documentJSON
	picks []int32 // universe indices used, for corpus-wide package stats
	edges int
}

// buildDocument generates document index (0-based) according to cfg.
func buildDocument(u *universe, cfg Config, index int) document {
	r := rand.New(rand.NewPCG(uint64(cfg.Seed)^documentStream, uint64(index)))

	picks := drawPackages(u, r, componentCount(cfg, r))
	primary := primaryComponent(r, index)
	edges := buildGraph(r, cfg, u, primary.BOMRef, picks)

	components := make([]json.RawMessage, len(picks))
	for i, p := range picks {
		components[i] = u.packages[p].fragment
	}

	bom := documentJSON{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: metadataJSON{
			Timestamp: corpusEpoch.Add(time.Duration(index) * time.Hour).Format(time.RFC3339),
			Tools:     toolsJSON{Components: []componentJSON{{Type: "application", Name: "gencorpus", Version: "1.0.0"}}},
			Component: primary,
		},
		Components:   components,
		Dependencies: edges,
	}
	if r.Float64() >= cfg.NoSerialRate {
		bom.SerialNumber = serialNumber(r)
	}

	total := 0
	for _, e := range edges {
		total += len(e.DependsOn)
	}
	return document{bom: bom, picks: picks, edges: total}
}

// revise returns the next revision of doc: same serial number, version bumped,
// and a small slice of its packages swapped out, the way a redeployed
// application produces a second SBOM.
func revise(u *universe, cfg Config, doc document, index int) document {
	r := rand.New(rand.NewPCG(uint64(cfg.Seed)^documentStream, uint64(index)|1<<62))

	picks := append([]int32(nil), doc.picks...)
	swaps := max(1, len(picks)/20)
	for range swaps {
		picks[r.IntN(len(picks))] = int32(r.IntN(len(u.packages)))
	}
	picks = dedupe(picks)

	primary := doc.bom.Metadata.Component
	edges := buildGraph(r, cfg, u, primary.BOMRef, picks)
	components := make([]json.RawMessage, len(picks))
	for i, p := range picks {
		components[i] = u.packages[p].fragment
	}

	bom := doc.bom
	bom.Version = doc.bom.Version + 1
	bom.Metadata.Timestamp = corpusEpoch.Add(time.Duration(index)*time.Hour + 24*time.Hour).Format(time.RFC3339)
	bom.Components = components
	bom.Dependencies = edges

	total := 0
	for _, e := range edges {
		total += len(e.DependsOn)
	}
	return document{bom: bom, picks: picks, edges: total}
}

// componentCount returns how many components this document carries, jittered
// around cfg.ComponentsPerDoc.
func componentCount(cfg Config, r *rand.Rand) int {
	if cfg.Jitter <= 0 {
		return cfg.ComponentsPerDoc
	}
	spread := float64(cfg.ComponentsPerDoc) * cfg.Jitter
	return max(1, cfg.ComponentsPerDoc+int(spread*(2*r.Float64()-1)))
}

// drawPackages picks n distinct universe entries. Most draws come from a Zipf
// distribution so a handful of packages land in nearly every document, the rest
// are uniform so the long tail is covered too.
func drawPackages(u *universe, r *rand.Rand, n int) []int32 {
	size := len(u.packages)
	if n > size {
		n = size
	}
	zipf := rand.NewZipf(r, zipfExponent, 1, uint64(size-1))
	seen := make(map[int32]bool, n)
	picks := make([]int32, 0, n)
	for attempts := 0; len(picks) < n && attempts < n*20; attempts++ {
		var idx int32
		if r.Float64() < hotDrawRate {
			idx = int32(zipf.Uint64())
		} else {
			idx = int32(r.IntN(size))
		}
		if seen[idx] {
			continue
		}
		seen[idx] = true
		picks = append(picks, idx)
	}
	// Heavy Zipf collision can exhaust the attempt budget; walk forward to fill.
	for idx := int32(0); len(picks) < n; idx++ {
		if !seen[idx] {
			seen[idx] = true
			picks = append(picks, idx)
		}
	}
	return picks
}

func dedupe(picks []int32) []int32 {
	seen := make(map[int32]bool, len(picks))
	out := picks[:0]
	for _, p := range picks {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// buildGraph wires the primary and the drawn components into a rooted DAG and
// returns the CycloneDX dependencies array. Node 0 is the primary; node i+1 is
// picks[i].
func buildGraph(r *rand.Rand, cfg Config, u *universe, primaryRef string, picks []int32) []dependencyJSON {
	refs := make([]string, len(picks)+1)
	refs[0] = primaryRef
	for i, p := range picks {
		refs[i+1] = u.packages[p].bomRef
	}

	parents := make([]int, len(refs))
	edges := make([][]int, len(refs))
	for i := 1; i < len(refs); i++ {
		parent := 0
		if i > 1 && r.Float64() >= directDependencyRate {
			parent = 1 + r.IntN(i-1)
		}
		parents[i] = parent
		edges[parent] = append(edges[parent], i)
	}
	for i := 2; i < len(refs); i++ {
		if r.Float64() >= crossEdgeRate {
			continue
		}
		from := r.IntN(i)
		if from == parents[i] {
			continue
		}
		edges[from] = append(edges[from], i)
	}
	if cfg.CycleRate > 0 && r.Float64() < cfg.CycleRate && len(refs) > 4 {
		addCycle(r, parents, edges)
	}

	out := make([]dependencyJSON, len(refs))
	for i, ref := range refs {
		dependsOn := make([]string, 0, len(edges[i]))
		for _, to := range edges[i] {
			dependsOn = append(dependsOn, refs[to])
		}
		out[i] = dependencyJSON{Ref: ref, DependsOn: dependsOn}
	}
	if cfg.DanglingRate > 0 && r.Float64() < cfg.DanglingRate {
		node := r.IntN(len(out))
		out[node].DependsOn = append(out[node].DependsOn, fmt.Sprintf("pkg:npm/vanished-%d@1.0.0", r.IntN(1000)))
	}
	return out
}

// addCycle points a node back at one of its own ancestors, so the dependents
// walk has to cope with a cycle it can actually reach from the primary.
func addCycle(r *rand.Rand, parents []int, edges [][]int) {
	node := 1 + r.IntN(len(parents)-1)
	ancestor := parents[node]
	if ancestor == 0 {
		return
	}
	if grandparent := parents[ancestor]; grandparent != 0 {
		ancestor = grandparent
	}
	edges[node] = append(edges[node], ancestor)
}

func primaryComponent(r *rand.Rand, index int) componentJSON {
	name := "acme-" + wordName(index) + "-service"
	version := fmt.Sprintf("%d.%d.%d", r.IntN(5)+1, r.IntN(20), r.IntN(20))
	purl := fmt.Sprintf("pkg:golang/github.com/acme/%s@v%s", name, version)
	return componentJSON{
		Type:     "application",
		BOMRef:   purl,
		Name:     name,
		Version:  "v" + version,
		Purl:     purl,
		Licenses: []licenseChoice{{License: &licenseObject{Name: "Acme Internal"}}},
	}
}

// serialNumber renders a deterministic RFC 4122-shaped urn for the document.
func serialNumber(r *rand.Rand) string {
	var b [16]byte
	for i := range b {
		b[i] = byte(r.UintN(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
