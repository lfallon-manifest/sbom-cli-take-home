# sbom-cli

sbom-cli ingests CycloneDX 1.6 JSON SBOMs into a local DuckDB file and answers two questions about the collection: which documents contain a given component (optionally pinned to one version), and which documents contain a component declared under a given license. The component query also walks each document's dependency graph and reports the transitive dependents of the match, so the answer is not just "this SBOM mentions X" but "these packages in this SBOM pull X in."

Everything is one binary and one `.duckdb` file. There is no server to run.

## Build

Requirements:

- Go 1.24 or newer.
- A C toolchain. The DuckDB driver (`github.com/marcboeker/go-duckdb/v2`) is a CGO binding that links prebuilt static libraries, so CGO must be enabled (the default) and a compiler must be present: Xcode Command Line Tools on macOS (`xcode-select --install`), gcc or clang on Linux.

```sh
go build -o sbom-cli .
```

The first build is slow because of the static DuckDB library; later builds hit the cache. The `sbom-cli` binary and `*.duckdb` files are gitignored.

### Portability and cross-compilation

The output is one self-contained binary. DuckDB is linked statically, and the only dynamic dependencies are the operating system's own C and C++ runtimes, so the binary can be copied to another machine of the same OS and architecture and run as is.

Building is less portable than running:

- `CGO_ENABLED=0` does not build. The driver has no pure-Go fallback.
- Cross-compiling needs a C cross toolchain for the target, not just `GOOS` and `GOARCH`. A plain `GOOS=linux go build` from macOS fails inside the Go runtime's cgo layer. The practical options are a native build per platform (a CI runner matrix) or a cross compiler such as `zig cc` or mingw-w64 supplied through `CC`.
- Supported targets are the ones the bindings ship static libraries for: darwin amd64 and arm64, linux amd64 and arm64, windows amd64.
- Windows needs a GCC-compatible toolchain. The Windows bindings are MinGW-style static archives linked with `--static` against libstdc++, Winsock, and the Restart Manager library, so the build requires MinGW-w64 (MSYS2 on Windows, or `CC=x86_64-w64-mingw32-gcc` for a cross build from Linux or macOS). MSVC cannot be used. There is no windows-arm64 bindings module, so Windows on ARM is unsupported by the driver today. The resulting `.exe` is statically linked and self-contained. This path was not exercised during the exercise; no Windows machine or MinGW toolchain was available.

## Usage

```
sbom-cli ingest <sbom-file>...
sbom-cli query --component <name> [--version <version>]
sbom-cli query --license <license>
```

`ingest` takes one or more files and processes them in order, each in its own transaction. The first failure stops the run; because re-ingest is a no-op, rerunning the same command after fixing the bad file picks up where it left off.

Global flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `--db <path>` | `./sbom.duckdb` | Database file. Created on first use. |
| `--json` | off | Emit JSON instead of the human-readable table. |

Matching rules:

- `--component <name>` is an exact, case-insensitive match on the component name. The purl is not searched.
- `--version <version>` is an exact, case-sensitive match. Version strings are opaque; there are no semver ranges.
- `--license <license>` is an exact, case-insensitive match against the SPDX ids extracted from each component's declared licenses. Expressions are tokenized at ingest, so `--license MIT` matches a component declared as `MIT OR Apache-2.0`.
- `--component` and `--license` in the same invocation is a usage error. The tool declines rather than guessing whether you meant AND or OR.

A query that runs successfully but finds nothing exits 0 with an empty result. Non-zero exit codes are reserved for real failures: unreadable file, malformed SBOM, bad flags.

Re-ingesting a byte-identical file is a no-op and is reported as already present. So is a serial-numbered SBOM whose content changed but whose `version` was not bumped, since documents with a serial number are keyed on serial plus version rather than on content.

## Example session

Output below is from a real run against the ten SBOMs in `examples/`.

```sh
$ go build -o sbom-cli .
$ ./sbom-cli ingest examples/*.cdx.json
Ingested github.com/acme/api-service (serial urn:uuid:7c5b4a9e-2f1d-4e8a-9b3c-6d2e1f0a8b7c, version 1)
  components: 13   new packages: 13   dependency edges: 13   dangling refs: 0
...
Ingested web-frontend (serial urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79, version 1)
  components: 13   new packages: 1   dependency edges: 14   dangling refs: 0

$ ./sbom-cli ingest examples/web-frontend.cdx.json
Already ingested web-frontend (serial urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79, version 1); no changes.

$ ./sbom-cli query --component lodash
DOCUMENT                     SERIAL                                         VER  COMPONENT       PACKAGE                 DEPENDENTS
github.com/acme/api-service  urn:uuid:7c5b4a9e-2f1d-4e8a-9b3c-6d2e1f0a8b7c  1    lodash@4.17.21  pkg:npm/lodash@4.17.21  github.com/acme/api-service@v2.3.0
legacy-monolith              urn:uuid:9b2e6f4a-1c3d-4e5f-8a7b-2c1d0e9f8a7b  1    lodash@4.17.15  pkg:npm/lodash@4.17.15  legacy-monolith@7.12.4
mobile-backend               -                                              1    lodash@4.17.21  pkg:npm/lodash@4.17.21  mobile-backend@0.9.3
web-frontend                 urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79  1    lodash@4.17.21  pkg:npm/lodash@4.17.21  web-frontend@1.4.0
web-frontend                 urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79  2    lodash@4.17.21  pkg:npm/lodash@4.17.21  web-frontend@1.4.0
5 hit(s) across 5 document(s).

$ ./sbom-cli query --component qs --version 6.11.0
DOCUMENT      SERIAL                                         VER  COMPONENT  PACKAGE            DEPENDENTS
web-frontend  urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79  1    qs@6.11.0  pkg:npm/qs@6.11.0  body-parser@1.20.2, express@4.19.2, web-frontend@1.4.0
web-frontend  urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79  2    qs@6.11.0  pkg:npm/qs@6.11.0  body-parser@1.20.2, express@4.19.2, web-frontend@1.4.0
2 hit(s) across 2 document(s).

$ ./sbom-cli query --license Apache-2.0
DOCUMENT                     SERIAL                                         VER  COMPONENT                          LICENSE     DECLARED
acme-data-pipeline           urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479  1    cryptography@42.0.5                Apache-2.0  Apache-2.0 OR BSD-3-Clause
acme-data-pipeline           urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479  1    python-dateutil@2.9.0              Apache-2.0  Apache-2.0
...
32 hit(s) across 6 document(s).

$ ./sbom-cli --json query --component lodash --version 4.17.15
[
  {
    "documentSerial": "urn:uuid:9b2e6f4a-1c3d-4e5f-8a7b-2c1d0e9f8a7b",
    "documentVersion": 1,
    "documentName": "legacy-monolith",
    "componentName": "lodash",
    "componentVersion": "4.17.15",
    "packageKey": "pkg:npm/lodash@4.17.15",
    "purl": "pkg:npm/lodash@4.17.15",
    "dependents": ["legacy-monolith@7.12.4"]
  }
]
```

The lodash rows show three things at once: the same package-version reached from four documents under three purl spellings (plain, uppercase type, and with qualifiers and a subpath) resolves to one canonical `PACKAGE`; a document with no serial number shows `-`; and both revisions of web-frontend (versions 1 and 2, same serial) are separate documents. DEPENDENTS lists the components that transitively depend on the match, nearest first. The `cryptography` row shows a component declared `Apache-2.0 OR BSD-3-Clause` matching `--license Apache-2.0` because expressions are tokenized at ingest.

`--json` emits the hits as an array using the field names in `internal/store/types.go`; an empty result is `[]`. With `ingest`, `--json` emits one array of per-file summaries.

## Scale testing

`examples/` is ten hand-written documents, each chosen for an edge case. Scale is a different question, so `scripts/gencorpus` generates a synthetic corpus for it: thousands of applications drawing their components from a shared universe of package-versions, so the same packages recur across documents the way a real fleet's dependencies do.

The corpus is not committed, only the script that produces it. `examples-large/` is gitignored.

```sh
go run ./scripts/gencorpus --out examples-large
./sbom-cli --db ./large.duckdb ingest examples-large/*.cdx.json
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--out <dir>` | `examples-large` | Output directory. Refuses to write into a non-empty one without `--force`. |
| `--documents <n>` | `2500` | Applications to generate. |
| `--components <n>` | `800` | Mean components per document, before jitter. |
| `--universe <n>` | derived | Distinct package-versions to draw from. The default gives each package-version about 50 occurrences across the corpus. |
| `--seed <n>` | `1` | The same seed regenerates byte-identical files. |
| `--jitter <f>` | `0.35` | Fraction to vary each document's component count by. |
| `--revision-rate <f>` | `0.15` | Share of applications that also emit a version-2 revision under the same serial number. |
| `--no-serial-rate <f>` | `0.05` | Share of documents with no `serialNumber`, so they key on content hash. |
| `--cycle-rate <f>` | `0.05` | Share of documents containing a dependency cycle. |
| `--dangling-rate <f>` | `0.03` | Share of documents containing a dangling dependency ref. |
| `--workers <n>` | one per CPU | Parallel document writers. |
| `--force`, `--quiet` | off | Overwrite a non-empty output directory; suppress progress. |

What the generated documents look like: each is a DAG rooted at the application, with about 6% of components as direct dependencies and the rest hanging off other components, a quarter of them with a second parent, so the transitive dependents walk has real work to do. Component draws are 70% Zipf and 30% uniform, which produces both package-versions present in nearly every document and a long tail drawn once or twice. Licenses follow a weighted distribution over SPDX ids, expressions with `OR` and `WITH`, name-only licenses, and no declaration at all. Names are synthetic (`quiet-lattice-4`, `github.com/fernbank/compact-cursor-2`) across npm, golang, maven, pypi, cargo, and deb, and 2% of package-versions carry no purl.

Output is deterministic, which is what makes it a benchmark: the same seed regenerates the same bytes, so a run can be repeated and re-ingesting a corpus is a no-op. Each corpus also gets a `corpus-manifest.json` recording the exact configuration, the resulting counts, and both ends of the reuse distribution, which is where to get hot and cold package names to query.

## More

- `DESIGN.md` covers the schema, query semantics, the DuckDB choice, scaling, and what was cut for time. Its scaling section carries the numbers measured against a generated corpus.
- `examples/README.md` describes each fixture SBOM and the edge case it exercises.
