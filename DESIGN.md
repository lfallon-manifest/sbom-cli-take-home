Source of truth for the submission design doc; the Google Doc is a paste of this file.

# sbom-cli design

## Overview

sbom-cli is a Go CLI that ingests CycloneDX 1.6 JSON SBOMs into a single-file DuckDB database and queries them by component name (optionally version) or by license. The stack is Go, Cobra for the command surface, cyclonedx-go for parsing, and DuckDB (via the go-duckdb CGO driver) as the embedded store. Beyond the literal brief, the component query walks each document's dependency graph and reports the transitive dependents of the match, and components are resolved to a canonical package identity shared across documents.

## CLI design

```
sbom-cli ingest <sbom-file>...
sbom-cli query --component <name> [--version <version>]
sbom-cli query --license <license>
```

Global flags: `--db <path>` (default `./sbom.duckdb`) selects the database file, and `--json` switches output from a human-readable table to JSON.

`ingest` accepts several files so a shell glob works directly. The store is opened once and each file is ingested in order in its own transaction. The first failure stops the run rather than continuing and summarizing: the error names the file, and since re-ingest is a no-op the fix is to rerun the same command. With `--json` the output is one array of per-file results, so the shape does not depend on how many files were given.

Matching rules were written down up front so the ingest and query work could proceed in parallel without guessing differently:

- `--component <name>`: exact match, case-insensitive, against the component name. purl is not searched; a separate `--purl` flag is the clean way to add that and is deferred.
- `--version <version>`: exact match, case-sensitive. Version strings are opaque; no semver ranges.
- `--license <license>`: exact match, case-insensitive, against the SPDX ids extracted from declared licenses. Because expressions are tokenized at ingest, `--license MIT` matches a component declared `MIT OR Apache-2.0`.
- `--component` and `--license` together: rejected with a usage error. Combining them is a reasonable feature, but silently choosing AND or OR is worse than declining. The right semantics can be added later without breaking anyone who relied on a guess.

Output defaults to a table because the primary consumer during the exercise is a person at a terminal. `--json` is opt-in for scripts and emits the `ComponentHit` and `LicenseHit` types from `internal/store/types.go` directly, so the JSON shape is the Go struct with no separate presentation layer to drift.

A query that runs and finds nothing exits 0. Zero hits is a correct answer, not a failure; non-zero exit codes are reserved for unreadable files, malformed SBOMs, and bad flags, so shell pipelines can distinguish "not found" from "broke."

## Database choice

DuckDB, persistent, one file.

Why:

- Single file, zero operations. `sbom-cli ingest` against a fresh directory just works; nothing to install or start.
- Real SQL. Recursive CTEs (for the transitive-dependents walk), window functions, views, and UNIQUE constraints are all available, so the interesting logic lives in the database rather than in Go loops.
- Columnar and vectorized. Analytical questions over the whole collection (how many documents contain any version of X, which licenses appear most) are DuckDB's native workload, and the same engine scales to millions of component rows on one machine.
- Embedded. The CLI stays one binary.

Tradeoffs:

- CGO. The driver links a prebuilt static DuckDB library, so a C toolchain is required and the first build is slow. The README calls this out. The binary that comes out is self-contained (DuckDB is static, only the OS C and C++ runtimes are dynamic), so distribution is one file per platform.
- Cross-compilation is not free. `GOOS`/`GOARCH` alone do not work; each target needs its own C toolchain or a native build. Targets are limited to what the bindings ship static libraries for (darwin and linux on amd64 and arm64, windows on amd64 only). Windows is the sharpest edge because it is an eventual requirement: the bindings are GCC-style archives linked fully static, so the build needs MinGW-w64 and cannot use MSVC, and there is no windows-arm64 module at all. The cost is a CI runner matrix (or a zig or mingw cross toolchain) rather than a single `go build` loop over targets.
- Single writer. One process holds the file for writing; concurrent ingest from many producers is not a DuckDB use case.
- Limited foreign key support. No cascading deletes and restricted updates, which shaped the schema (see the root component discussion below).
- Not a server. There is no network access, no auth, no multi-user story. That is fine for a CLI and is the first thing to change at scale.

The fallback, had the CGO build failed, was SQLite via `modernc.org/sqlite` (pure Go, no CGO). The schema is portable, and both the recursive CTE and the derived document key work unchanged in SQLite. The build succeeded, so the fallback was never exercised. It remains the exit if Windows support arrives and the MinGW toolchain cost proves unacceptable: a pure-Go store cross-compiles to every Go target with no C compiler at all, and the swap is contained to `internal/store` because the CLI codes against the `Store` interface.

## Data model

Three tiers: documents (one SBOM), packages (canonical package-version identity, shared across documents), and components (one occurrence of a package inside one document). Dependency edges connect components within a document. Licenses are a small dimension joined to components through `component_licenses`.

```
documents                              packages   (canonical package-version)
  id             PK                      id            PK
  document_key   UNIQUE, derived         package_key   UNIQUE, derived
  serial_number  NULLable                purl          NULLable
  version        default 1               type, group_name, name, version
  spec_version                           first_seen_at
  document_name
  source_path
  content_hash   NOT NULL
  ingested_at

components                             licenses
  id                   PK                id            PK
  document_id          FK documents      license_key   UNIQUE, derived
  package_id           FK packages       spdx_id       NULLable
  parent_component_id  NULLable          name          NULLable
  bom_ref              NOT NULL
  is_primary           BOOLEAN
  UNIQUE (document_id, bom_ref)

component_licenses                     dependencies
  component_id     FK components         document_id        FK documents
  license_id       FK licenses           from_component_id  FK components
  raw_expression   NULLable              to_component_id    FK components
  declared_source  'id'|'name'|'expression'
  PK (component_id, license_id)          PK (document_id, from_, to_)

latest_documents  (view)  newest version per serial_number; unserialed docs always included
```

Indexes cover the query paths: `packages(name)`, `components(package_id)`, `components(document_id)`, `dependencies(to_component_id)`, and `component_licenses(license_id)`. The schema is embedded in the binary and applied idempotently on every open. The full DDL is `internal/store/schema.sql`.

### The root component

`metadata.component` is the software the SBOM is about, and it is not a member of the `components` array. It is inserted as a normal `components` row with `is_primary = true`. This is load-bearing: CycloneDX dependency graphs are almost always rooted at the primary component's `bom-ref`, so skipping the insert would dangle every root edge and the transitive-dependents walk would lose its top.

### No `documents.primary_component_id`

Pointing documents at components while components point back at documents is a circular foreign key, and DuckDB's FK support is limited (no cascade, restricted updates). The `is_primary` flag does the same job with no cycle. `parent_component_id` is likewise left as a plain integer rather than a declared self-referencing FK for the same reason.

### Synthesized `bom-ref`

`bom-ref` is optional in the spec. A missing one is synthesized (`synthetic:<n>`) at ingest so `UNIQUE (document_id, bom_ref)` stays satisfiable and every component is addressable.

### Nested components

CycloneDX permits `components[].components` to arbitrary depth. `parent_component_id` preserves that nesting with one nullable column rather than silently flattening it.

### Derived package identity (`package_key`)

purl is optional, so canonical identity cannot be keyed on it. `package_key` is computed at ingest:

- purl present: the purl with `type` and `namespace` lowercased, qualifiers and subpath stripped, version kept. `pkg:npm/Foo@1.2.3?arch=x64` becomes `pkg:npm/Foo@1.2.3`.
- purl absent: `generic:{group}/{name}@{version}`, with empty segments collapsed.

Two components collapse to one package only if their `package_key` matches exactly. This is deliberately conservative: a component with no purl never merges with one that has a purl, even if name and version agree, because a purl carries ecosystem information that a bare name does not.

Case handling is narrow on purpose. purl `type` and `namespace` are safe to lowercase, but `name` case sensitivity is ecosystem-dependent, and lowercasing wholesale would merge distinct Maven artifacts. So only type and namespace are lowercased, and case-variant duplicates of the same artifact do not merge. That residual risk is accepted and listed under limitations.

### `packages` is really package-version

The table is named `packages` and holds a `version` column, so each row is one package at one version. That is a naming compromise for the hour. A real system separates `package` from `package_version`; the scaling section covers what that unlocks.

### Licenses and `license_key`

CycloneDX allows three license shapes: `{license: {id}}`, `{license: {name}}`, and `{expression: "MIT OR Apache-2.0"}`. The `licenses` table holds one row per distinct license, keyed by a single derived non-null `license_key` (`spdx:mit` for an SPDX id, `name:<lowercased name>` for a free-text name). A natural key over the nullable `spdx_id` and `name` columns was rejected because SQL treats NULLs as distinct under UNIQUE, so a multi-column nullable key would not deduplicate at all.

### License expression tokenization

Expressions are tokenized at ingest into one `component_licenses` row per extracted SPDX id, with the original expression preserved in `raw_expression` and the shape it came from in `declared_source`. That is what makes `--license MIT` match a component declared `MIT OR Apache-2.0`. Tokenization is deliberately naive: split on `OR`, `AND`, `WITH`, and parentheses. Operator semantics are ignored; see limitations.

`raw_expression` and `declared_source` live on the join row, not on `licenses`, because the expression is a property of how this component declared its license in this document. The same license row is shared by every component that references MIT, however each of them phrased it.

### Dependencies

Edges are stored per document because the same package resolves to different dependencies in different applications. An edge whose `ref` or `dependsOn` points at a `bom-ref` absent from the document is skipped and counted; the count is reported at the end of ingest (`IngestResult.DanglingRefs`) rather than failing the whole document over one bad ref.

### Document identity and re-ingest

`serialNumber` is optional, and both syft and cdxgen generate a new UUID every run while leaving `version` at 1. Keying documents on `(serial_number, version)` alone would make every regenerated SBOM of the same software look like an entirely new document, and revision history would only ever fire on hand-crafted fixtures. Keying on `serial_number` alone is worse: two revisions of one SBOM share a serial and differ only in `version`, so they would collide on the UNIQUE constraint and the `latest_documents` view would have nothing to choose between.

So `document_key` is derived at ingest: `serial:<serialNumber>@<version>` when a serial number is present, otherwise `sha256:<content_hash>`. `content_hash` is always stored regardless of which branch produced the key. Re-ingesting a byte-identical file is detected through `document_key` under either branch, reported as `AlreadyPresent`, and writes nothing. That is the honest dedupe: the tool can say two files are the same bytes, and it does not pretend to know that two differently generated files describe the same software. The cost of trusting the serial is that a serial-numbered file whose content changed but whose `version` was not bumped is also treated as already present; the publisher said it was the same revision, and the tool takes their word for it.

Because the serial branch includes `version`, each revision of a serial-numbered SBOM is its own row, and the `latest_documents` view picks the newest one where publishers do maintain serial numbers across revisions:

```sql
CREATE VIEW latest_documents AS
  SELECT * FROM documents d
  WHERE d.serial_number IS NULL
     OR d.version = (SELECT MAX(version) FROM documents WHERE serial_number = d.serial_number);
```

A richer drift model would group snapshots by subject (primary component name and version) on an `ingested_at` timeline, since that survives regeneration. That is deferred and not built. CycloneDX revision history is a modeling choice that the generated fixtures do not exercise.

## Query semantics

`--component <name> [--version <v>]` returns, for each matching component in each document:

1. the document that contains it (serial, version, name), the component's name and version, its `package_key`, and its purl if any; and
2. the ancestor components within that document that transitively depend on it, via a recursive CTE walking `dependencies` from `to_component_id` back to `from_component_id`, rendered as `name@version` strings, nearest first.

The second half is the answer to "documents or packages" in the brief. Without it the query would say which SBOMs mention the component but not which packages in them pull it in.

The recursive CTE needs a cycle guard because real dependency graphs occasionally contain cycles, and `UNION ALL` with no guard does not terminate. The walk uses `UNION` to dedupe intermediate rows and caps depth at 64 hops. The cap is the load-bearing half: `UNION` dedupes `(target, ancestor, depth)` tuples, and each lap around a cycle produces a new depth, so on its own `UNION` would not stop the walk. A final `GROUP BY` with `MIN(depth)` collapses the laps and gives the nearest-first ordering. The cyclic fixture in `examples/` (`hyper > http > bytes > hyper`) returns in about 20ms and has a unit test with a 10s timeout to prove termination.

The table shows the canonical `package_key` rather than the stored purl. The `packages` row keeps the first raw purl that introduced the package-version, which can carry one document's qualifiers and subpath, so showing it next to a hit from a different document would be misleading. The JSON output includes both.

`--license <license>` returns one row per component per document whose extracted SPDX ids include the given id (case-insensitive), with the matched id and the `raw_expression` it was extracted from. There is no dependents walk for license hits.

`ComponentHit.Dependents` is a flat list of `name@version` strings. That loses hop depth and branching: a direct dependent and a fifth-level ancestor look the same. Acceptable for the hour; the recursive CTE has the depth available if a richer rendering is wanted.

## Ingest strategy

Parsing happens in Go with cyclonedx-go, and DuckDB receives rows through batched inserts. The plan originally assumed SQL-first ingest via DuckDB's `read_json` on the theory that it would keep the Go side thin. That was reversed for three reasons:

- cyclonedx-go already models 1.6, including the license choice union and arbitrarily nested `components[].components`. Flattening arbitrarily nested arrays in SQL needs recursive JSON unnesting, which is genuinely painful.
- SQL-first ingest was simultaneously the plan's top named risk and the only justification for dropping unit tests. That is a bad combination for a load-bearing decision.
- With parsing in Go, `package_key` derivation and license tokenization become ordinary pure functions, which are cheap to test.

The cost is more Go code, but it is mechanical code with no unknowns.

Each ingest runs inside one transaction: the document row, the primary component, every component, every license row and join row, and every dependency edge either all commit or none do. Malformed input (unparseable JSON, a structure cyclonedx-go rejects) fails the ingest with a clear message and leaves the database exactly as it was. Dangling dependency refs are the one soft failure: they are skipped and counted, not fatal.

## Scaling to thousands of SBOMs and millions of components

Thousands of SBOMs at a few thousand components each is millions of `components` rows, a comparable number of `dependencies` rows, and a `packages` table that grows much more slowly because the same package-versions recur across documents. The design already leans toward that shape; the deployment does not.

### Measured against a generated corpus

`scripts/gencorpus` generates that shape so the claims below are not guesses. Its defaults produce 2,500 applications averaging 800 components: 2,846 files (346 of them revisions), 2,274,954 component occurrences, 2,835,379 dependency edges, and 42,500 distinct package-versions, in 745 MB of JSON. Writing it takes 1.4 seconds on a 12-core M-series laptop. See the README for the flags and the shape of the generated documents.

Ingest is three orders of magnitude slower than query, and it is the only thing that needs work:

| | Measured |
|---|---|
| Generate the corpus | 1.4 s for 2.27M components (parallel, 12 workers) |
| Ingest, complete run | 226 files / 175,675 components in 2 m 28 s, i.e. **~1,190 components/s** |
| Ingest, large corpus | 1.33 documents/s sustained ~320 documents in, i.e. ~1,070 components/s; the full 2.27M corpus extrapolates to **~35 minutes** |
| Database size | ~0.5 KB per component row, so ~1.2 GB for the full corpus |
| `--component` on a package in 358 documents, with the transitive dependents walk | **0.25 s** |
| `--component` on a mid-frequency package (109 documents) | 0.33 s |
| `--license GPL-3.0-only`, 6,292 hits | 0.08 s |
| `--license MIT`, 133,993 hits, 34 MB of JSON | 0.46 s |

Query numbers are against a partially loaded database (~320 documents, ~275k components) because the full ingest was stopped early; they are the right order of magnitude but the full corpus was not queried. The ingest number is what matters and it was measured twice, on a complete small run and part-way into the large one, with only mild degradation as the tables grew.

The read path is already in good shape: the recursive dependents walk over a package present in every document, which was the thing this section predicted would hurt, costs a quarter of a second at this size. Ingest is the bottleneck, and for the reason the design predicted:

- Every component is one `INSERT ... RETURNING id`, every license join row and every dependency edge one more `INSERT`. That is roughly 7 million single-row statements for the full corpus, each a CGO round trip into an engine whose worst case is row-at-a-time appends. Bulk loading per document, via go-duckdb's appender or a multi-row `VALUES` list, is the single biggest win available and needs ids assigned in Go rather than by `RETURNING`.
- The `packages` and `licenses` id caches live on the per-document `ingester`, so each document re-runs a point lookup for every package it holds even though the corpus only has 42,500 of them and the log shows `new packages: 0` for most documents. Hoisting those caches onto `DuckStore` turns ~2.3M lookups into ~42,500 with no schema change.
- Prepared statements are rebuilt per document (2,846 × 3) rather than once per store.
- Parsing 745 MB of JSON and writing to a single-writer database both happen on one goroutine. Parsing is embarrassingly parallel, so a parse-ahead pipeline feeding one writer overlaps the two.

None of that changes the schema or the query semantics, which is why it is worth doing before the deployment changes below.

### What already scales

- Canonical `packages` keeps `components` narrow. A component row is five small columns (two FKs, a nullable parent, a short `bom_ref`, a boolean). Name, version, purl, and type are stored once per package-version, not once per occurrence. Across thousands of SBOMs of related applications, `packages` converges while `components` grows linearly, which is the right shape.
- Columnar storage. `--license` is a filter on `licenses.license_key` joined through `component_licenses` to `components` to `documents`; every one of those is a scan over narrow integer columns, which is exactly what a vectorized columnar engine does well. Fleet-wide analytics (license distribution, most common package-versions, documents per package) are the same shape.
- Indexes sit on the query paths: `packages(name)` for the component lookup, `components(package_id)` to fan out from a package to its occurrences, `dependencies(to_component_id)` for the backwards walk the recursive CTE does, and `component_licenses(license_id)` for the license lookup.
- Ingest is batched per document inside one transaction, and a duplicate `document_key` means no component, license, or dependency rows are written for that file. Parsing is in Go, so the database only ever sees prepared rows.

### What changes first

Separate package from package-version. Today `packages(package_key, purl, type, group_name, name, version)` is one row per version. Split it into `packages(id, type, group_name, name)` and `package_versions(id, package_id, version, purl, package_key)`, and point `components.package_id` at `package_versions`. That makes "all versions of X" a join instead of a `DISTINCT` over a string column, gives version-range queries a table to run over, and is where the deferred `--all-versions` flag belongs.

Move off one DuckDB file. DuckDB is single-process and single-writer, and the moment ingest comes from many CI pipelines at once that is the wall. Two workable shapes, both of which keep the schema:

- Postgres as the system of record. Sequences become identity columns, `parent_component_id` gets a real FK, the recursive CTE runs unchanged. Point queries (`--component`, `--license`) stay on Postgres.
- Postgres for transactional ingest and point queries, with DuckDB kept as the analytical layer over Parquet in object storage. Export `components`, `dependencies`, and `component_licenses` partitioned by ingest date or tenant; DuckDB readers query the Parquet directly for fleet-wide questions without touching the transactional database.

Ingest becomes a queue-driven pipeline. Producers upload an SBOM to object storage and publish a message; stateless workers parse with cyclonedx-go, compute `content_hash`, and write. Because `document_key` is UNIQUE and derived from the file itself (serial number plus version, or the content hash), retries and duplicate deliveries are no-ops without any extra idempotency machinery. Workers scale horizontally because parsing is already in Go, not in the database. Row-at-a-time inserts become `COPY` or bulk load per document.

The transitive-dependents walk needs a different strategy over millions of edges. For a package that appears in most documents (a common logging or JSON library), the recursive CTE fans out across every document at once. Two options:

- Materialize the transitive closure per document at ingest: `component_ancestors(document_id, component_id, ancestor_id, depth)`. Documents are immutable once written (re-ingest is either a no-op or a new document row), so the closure is write-once and never needs invalidation. Cost is roughly edges times depth rows per document, which is small per document and only grows with the collection.
- Keep the recursive query but bound depth and paginate by document, so one query touches one document's edge set at a time.

The first also restores hop depth to the output, which the flat `Dependents` list currently loses.

Output needs a bound. `--license MIT` already returns 133,993 rows and 34 MB of JSON against a fifth of the generated corpus, and every hit is materialized into a slice before anything is printed. A `--limit`, a `--count`, or streaming output is needed before the collection gets much larger.

Name and purl lookups need real indexes. `--component` compares `lower(packages.name)`, which the plain `packages(name)` index cannot serve. Either add a normalized `name_lower` column and index that, or use an expression index (`CREATE INDEX ON packages (lower(name))` in Postgres). The deferred `--purl` flag wants an index on `purl` or on `package_key`, which already has one via UNIQUE. Prefix or fuzzy name search, if wanted, is a trigram index.

Vulnerability-style queries want a `package_versions` dimension. "Which documents contain a package-version affected by advisory X" is a join from an advisory table through `package_versions` to `components` to `documents`. With the split above, that join is on integer keys and never scans `components` by string; the affected set can also be precomputed per advisory as a table of `package_version_id`s.

API and multi-tenancy. The CLI becomes a thin client to an HTTP API. `documents` gains an owner or tenant column and every query filters on it first. `components`, `dependencies`, and `component_licenses` are per-document, so they partition cleanly by tenant or by document id range (Postgres declarative partitioning, or a `tenant=/date=` directory layout for Parquet). `packages` and `licenses` are global shared dimensions, or per-tenant if isolation requires it.

Observability on ingest. `IngestResult` already reports `DanglingRefs`, `NewPackages`, and `AlreadyPresent`. At scale those become metrics: dangling ref rate per SBOM generator identifies broken tooling upstream, `NewPackages` per ingest trending toward zero shows the canonical table converging, and parse failure rate by spec version shows what the parser does not handle. Parse failures get logged with the `content_hash` so any failure is reproducible from the stored file.

## Limitations imposed by the 1-hour box

Testing. No TDD on this exercise; the time box did not allow red-green-refactor. Each work stream wrote tests alongside its code rather than ahead of it: table-driven tests for the pure functions in `internal/normalize`, ingest tests over a small fixture in `internal/store/testdata`, query tests over hand-seeded rows (including the cycle), and command-layer tests against a fake store. That is 85 tests in 4 packages. What is missing is an integration test over `examples/`; that verification was a manual end-to-end run of the real binary against all 10 fixtures, recorded in the README. This is a deliberate deviation from the usual discipline, and the plan said so up front.

Modeling and behavior:

- CycloneDX revision history is modeled (`serial_number`, `version`, the `latest_documents` view) but not exercised by generated SBOMs, because syft and cdxgen regenerate `serialNumber` every run.
- A serial-numbered SBOM whose content changed but whose `version` was not bumped is treated as already present and not re-ingested, because the document key trusts the publisher's serial and version over the file bytes.
- `packages` is really package-version. A real system separates the two.
- purl `name` case is preserved to avoid merging distinct Maven artifacts, so case-variant duplicates of the same artifact will not merge.
- `Dependents` renders as flat `name@version` strings and loses hop depth.
- CycloneDX 1.6 JSON only. No SPDX 3.0, no CycloneDX XML.
- License expression tokenization ignores operator semantics. `--license MIT` matches `MIT OR Apache-2.0` even though the component may not actually be distributed under MIT, and `WITH` is treated as just another separator rather than as an exception qualifier, so `Classpath-exception-2.0` ends up stored as if it were a license id.
- Subpath stripping merges things a consumer might want kept apart. syft emits platform-specific Go submodules as purl subpaths (`pkg:golang/github.com/duckdb/duckdb-go-bindings@v0.1.21#darwin-arm64`, `#linux-amd64`, and so on), and they all collapse to one package-version. The syft fixture has 30 components and 23 canonical packages for that reason. Correct under the design, but a real system would keep the subpath as an attribute of the component.
- `packages.purl` holds whichever raw purl first introduced the package-version, qualifiers included. `package_key` is the identity; `purl` is informational.
- `--license` also matches name-only licenses (`--license "Custom Proprietary License"`), which goes slightly beyond the stated SPDX-id rule. It fell out of the `license_key` design for free and was kept.
- `--json` is a global flag, so `sbom-cli --json query ...` and `sbom-cli query ... --json` both work. Persistent flags in Cobra allow either position.
- Only the macOS arm64 build was exercised. Linux and Windows builds are supported by the bindings but were not produced here, and the Windows path in particular (MinGW-w64, no MSVC, amd64 only) is documented from the bindings' link flags rather than from a successful build. Windows support is an eventual requirement, so the first CI change is a runner matrix that proves all three operating systems build and pass the suite.

Deferred, not built:

- `--purl` query flag.
- `--all-versions` on queries.
- Combining `--component` and `--license` in one query.
- Ingesting a directory (multiple file arguments are supported; directory walking is not).
- Subject-keyed drift timeline, grouping snapshots by primary component name and version.

## How AI tools were used

Two phases, both with Claude Code (Fable 5.1). Prompt history was not curated as the work went, so this is written from memory.

### Planning, before the clock started

`PROMPT.md` in the repo is the plan. It was written in conversation with Claude ahead of the implementation session and is where most of the design judgment happened: the three-tier data model, the derived keys, the decision to parse in Go instead of SQL-first, the matching rules, the work streams with their dependency order, the triage tiers, and the decision gates. Writing the matching rules down before any code existed is what let the ingest and query streams run in parallel without guessing differently. The `Store` interface and result types were also settled in the plan.

### Implementation, roughly 30 minutes of wall clock

Claude Code acted as a coordinator that wrote the schema and store scaffolding by hand, then launched five subagents in parallel, one per work stream: fixtures, ingest plus the normalize package, query, the Cobra CLI, and the docs. Each agent had strict file ownership, a written contract for what it produced, and instructions not to touch git or `go mod`. The coordinator reconciled at the end: ran the full suite, ran the real binary against every fixture, fixed the display issue that only shows up when the pieces meet, updated the docs with actuals, and made the commits.

What worked:

- Parallel streams against a settled interface. Ingest and query never saw each other's code and composed on the first try. The query stream wrote its tests against hand-seeded rows, the CLI stream against a fake store, so neither waited on ingest.
- Agents finding each other's bugs. The query agent hit a schema loader that split statements on every semicolon, including the ones inside comments, which broke every `Open`. It patched the comments and reported it; the coordinator fixed the loader properly.
- The fixture agent's report. It came back with exact expectations (which package appears in how many documents, at which versions, where the cycle is, which refs dangle), which turned the end-to-end run into a checklist rather than a judgment call.
- Real generated data. syft and cdxgen output surfaced shapes the hand-crafted fixtures did not: no `dependencies` key at all, a primary component with no version, an empty-string version, platform submodules as purl subpaths.

What did not work, or needed a human in the loop:

- The plan had a bug. `document_key = COALESCE(serial_number, hash)` collides when two revisions share a serial number and differ only in version, which is the exact case the `latest_documents` view exists for. It was caught while briefing the ingest agent, but the docs agent had already written the old rule and needed a mid-flight correction.
- Hand-written glue was the weakest code. The schema splitter above was the coordinator's, not an agent's.
- Docs drafted from the plan drift from the code. The docs agent worked from `PROMPT.md` and `schema.sql` before any behavior existed, so the depth cap, the test coverage story, and several limitations had to be reconciled afterwards. Cheap to fix, but the draft is not the deliverable.
- Nobody owns the seams. The PACKAGE column showed the first-seen raw purl, qualifiers included, next to hits from other documents. Every agent's slice was correct in isolation; the problem only appears when ingest, query, and rendering meet, and only the coordinator sees that.
- Shell trivia still costs time. The first end-to-end run silently ingested one file because a zsh glob with no match aborted the loop. The rerun was fine, but an agent reading "1 hit across 1 document" could easily have believed it.

On testing: the plan said no TDD, and there was none in the red-green sense. Each agent wrote tests alongside its code without being asked to, which is why the suite exists at all.
