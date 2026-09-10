package corpus

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
)

// pkg is one package-version in the corpus universe. The CycloneDX component
// object is rendered once, at universe build time, so writing a document that
// uses the package is a byte copy rather than an encode.
type pkg struct {
	bomRef   string
	name     string
	version  string
	fragment json.RawMessage
}

func (p pkg) label() string { return p.name + "@" + p.version }

// universe is the pool of package-versions every document draws from. It is
// deliberately much smaller than the total component count so the same
// package-versions recur across documents, which is what the canonical
// packages table is designed for.
type universe struct {
	packages []pkg
}

// ecosystems and their share of the generated names, roughly matching what a
// mixed fleet of applications looks like.
var ecosystems = []struct {
	purlType string
	share    int
}{
	{"npm", 34}, {"golang", 22}, {"maven", 16}, {"pypi", 14}, {"cargo", 9}, {"deb", 5},
}

var (
	adjectives = []string{
		"async", "atomic", "binary", "bright", "clever", "compact", "cosmic", "crisp",
		"dual", "eager", "elastic", "fluent", "frozen", "gentle", "hidden", "hollow",
		"idle", "iron", "keen", "lazy", "light", "linear", "liquid", "lucid",
		"modular", "narrow", "nested", "nimble", "opaque", "polar", "prime", "quiet",
		"rapid", "rustic", "sharp", "silent", "solid", "sparse", "stable", "static",
		"steady", "swift", "tidy", "tiny", "vivid", "warm", "wide", "zonal",
	}
	nouns = []string{
		"anchor", "beacon", "bridge", "buffer", "cache", "canvas", "cipher", "cluster",
		"conduit", "cursor", "digest", "engine", "envoy", "fabric", "ferry", "forge",
		"gateway", "girder", "harbor", "helix", "index", "kernel", "ladder", "lantern",
		"ledger", "lattice", "marker", "matrix", "meridian", "mirror", "nexus", "orbit",
		"parser", "pilot", "pivot", "prism", "quarry", "relay", "ripple", "router",
		"scaffold", "sentry", "shuttle", "signal", "socket", "spindle", "stream", "vault",
	}
	orgs = []string{
		"acmelabs", "bitforge", "cloudkite", "datawright", "elmwood", "fernbank",
		"glacierio", "harborworks", "ionflux", "juniperlabs", "kestrel", "lumenstack",
	}
)

// wordName builds a unique lowercase "adjective-noun" name for index i, adding a
// numeric suffix once the word pairs run out.
func wordName(i int) string {
	pairs := len(adjectives) * len(nouns)
	base := adjectives[i%len(adjectives)] + "-" + nouns[(i/len(adjectives))%len(nouns)]
	if round := i / pairs; round > 0 {
		return fmt.Sprintf("%s-%d", base, round+1)
	}
	return base
}

// licenseChoice mirrors the CycloneDX licenses[] entry: either a license object
// or an SPDX expression.
type licenseChoice struct {
	License    *licenseObject `json:"license,omitempty"`
	Expression string         `json:"expression,omitempty"`
}

type licenseObject struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func spdxID(id string) []licenseChoice {
	return []licenseChoice{{License: &licenseObject{ID: id}}}
}

func spdxExpr(expr string) []licenseChoice { return []licenseChoice{{Expression: expr}} }

// licenseWeights is the declared-license distribution, weighted so MIT and
// Apache-2.0 dominate the way they do in the wild. A nil entry means the
// component declares no licenses at all.
var licenseWeights = []struct {
	weight  int
	choices []licenseChoice
}{
	{45, spdxID("MIT")},
	{20, spdxID("Apache-2.0")},
	{8, spdxID("BSD-3-Clause")},
	{5, spdxID("ISC")},
	{4, spdxExpr("MIT OR Apache-2.0")},
	{3, spdxExpr("Apache-2.0 OR BSD-3-Clause")},
	{3, spdxID("BSD-2-Clause")},
	{2, spdxID("MPL-2.0")},
	{2, spdxID("GPL-3.0-only")},
	{2, spdxID("LGPL-2.1-or-later")},
	{1, spdxExpr("GPL-2.0-only WITH Classpath-exception-2.0")},
	{1, []licenseChoice{{License: &licenseObject{Name: "Custom Proprietary License"}}}},
	{1, spdxID("Unlicense")},
	{3, nil},
}

// componentJSON is the shape written for each component and for the primary.
type componentJSON struct {
	Type     string          `json:"type"`
	BOMRef   string          `json:"bom-ref"`
	Group    string          `json:"group,omitempty"`
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Purl     string          `json:"purl,omitempty"`
	Licenses []licenseChoice `json:"licenses,omitempty"`
}

// noPurlRate is the share of package-versions distributed without a package
// URL, which exercises the name-based package key path at scale.
const noPurlRate = 0.02

// buildUniverse creates size package-versions deterministically from seed.
func buildUniverse(size int, seed int64) (*universe, error) {
	r := rand.New(rand.NewPCG(uint64(seed), universeStream))
	u := &universe{packages: make([]pkg, 0, size)}

	shareTotal := 0
	for _, e := range ecosystems {
		shareTotal += e.share
	}

	for nameIndex := 0; len(u.packages) < size; nameIndex++ {
		purlType := ecosystems[len(ecosystems)-1].purlType
		roll := r.IntN(shareTotal)
		for _, e := range ecosystems {
			if roll < e.share {
				purlType = e.purlType
				break
			}
			roll -= e.share
		}
		for _, version := range versionsFor(r) {
			if len(u.packages) == size {
				break
			}
			u.packages = append(u.packages, buildPackage(r, purlType, nameIndex, version))
		}
	}
	if len(u.packages) == 0 {
		return nil, fmt.Errorf("universe size %d produced no packages", size)
	}
	// Names are built by walking the word lists in order, and documents draw
	// hot packages from the low indices, so without a shuffle every popular
	// package would share the same noun.
	r.Shuffle(len(u.packages), func(i, j int) {
		u.packages[i], u.packages[j] = u.packages[j], u.packages[i]
	})
	return u, nil
}

// versionsFor returns the version strings one package name is published under.
// Most names have a single version in play; a few have two or three, which is
// what makes --component without --version interesting.
func versionsFor(r *rand.Rand) []string {
	count := 1
	switch roll := r.IntN(10); {
	case roll >= 9:
		count = 3
	case roll >= 6:
		count = 2
	}
	major, minor, patch := r.IntN(9), r.IntN(30), r.IntN(30)
	versions := make([]string, count)
	for i := range versions {
		versions[i] = fmt.Sprintf("%d.%d.%d", major, minor+i*2, patch)
	}
	return versions
}

func buildPackage(r *rand.Rand, purlType string, nameIndex int, version string) pkg {
	base := wordName(nameIndex)
	org := orgs[nameIndex%len(orgs)]

	var group string
	name := base
	switch purlType {
	case "golang":
		name = "github.com/" + org + "/" + base
		version = "v" + version
	case "maven":
		group = "com." + org
	case "pypi":
		name = strings.ReplaceAll(base, "-", "_")
	}

	comp := componentJSON{
		Type:     "library",
		Group:    group,
		Name:     name,
		Version:  version,
		Licenses: pickLicenses(r),
	}
	if r.Float64() < noPurlRate {
		comp.BOMRef = bomRefWithoutPurl(group, name, version)
	} else {
		comp.Purl = buildPurl(purlType, group, name, version)
		comp.BOMRef = comp.Purl
	}

	fragment, err := json.Marshal(comp)
	if err != nil {
		// componentJSON has no field that can fail to marshal.
		panic("corpus: marshal component: " + err.Error())
	}
	return pkg{bomRef: comp.BOMRef, name: name, version: version, fragment: fragment}
}

func buildPurl(purlType, group, name, version string) string {
	switch purlType {
	case "maven":
		return fmt.Sprintf("pkg:maven/%s/%s@%s", group, name, version)
	case "deb":
		return fmt.Sprintf("pkg:deb/debian/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	}
}

func bomRefWithoutPurl(group, name, version string) string {
	if group != "" {
		return fmt.Sprintf("%s:%s:%s", group, name, version)
	}
	return fmt.Sprintf("%s:%s", name, version)
}

var licenseWeightTotal = func() int {
	total := 0
	for _, w := range licenseWeights {
		total += w.weight
	}
	return total
}()

func pickLicenses(r *rand.Rand) []licenseChoice {
	roll := r.IntN(licenseWeightTotal)
	for _, w := range licenseWeights {
		if roll < w.weight {
			return w.choices
		}
		roll -= w.weight
	}
	return nil
}
