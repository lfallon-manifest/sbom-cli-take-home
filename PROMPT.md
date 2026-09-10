# Manifest Take Home Exercise

Take-home for an internal position: a CLI tool that ingests and queries SBOMs, with room
for extra functionality. Target is ~1 hour, so the plan below is optimized for
parallelizable work streams and a thin vertical slice first.

## Implementation

- Language: Go
- Database: DuckDB (persistent, single file). Requires CGO; note this in the README.
- CLI framework: Cobra
- SBOM parsing: `cyclonedx-go`
- SBOM format: CycloneDX 1.6 (JSON)

## Assumptions

1. **Not every component has a purl.** Canonical package identity cannot be keyed on purl.
   See `package_key` below.
2. A component's declared license is a property of that component *in that document*, not
   of the package globally. The same package can be declared under different licenses in
   different SBOMs.
3. Input SBOMs are CycloneDX 1.6 JSON and well-formed enough to parse. Malformed input
   fails the ingest with a clear message rather than partially committing.
4. `bom-ref` and `serialNumber` are both optional in the spec, so neither can be assumed
   present as a key. Both need a synthesized fallback.

## Data Model

Three tiers: **documents** (an SBOM), **packages** (canonical software identity, shared
across documents), **components** (one occurrence of a package inside one document).
Dependency edges connect components within a document.

```
documents                            packages   (canonical package-version)
  id                      PK           id                    PK
  document_key            UNIQUE       package_key           UNIQUE  <- derived
  serial_number           NULLable     purl                  NULLable
  version                              type, group, name, version
  spec_version                         first_seen_at
  document_name
  source_path
  content_hash
  ingested_at

components                           licenses
  id                      PK           id                    PK
  document_id             FK           license_key           UNIQUE  <- COALESCE-derived
  package_id              FK           spdx_id               NULLable
  parent_component_id     FK NULLable  name                  NULLable
  bom_ref
  is_primary              BOOLEAN
  UNIQUE (document_id, bom_ref)

component_licenses                   dependencies
  component_id            FK           document_id           FK
  license_id              FK           from_component_id     FK
  raw_expression          NULLable     to_component_id       FK
  declared_source                      PK (document_id, from_, to_)
  PK (component_id, license_id)
```

### The root component

`metadata.component` is the software the SBOM is *about*, and it is **not** a member of the
`components` array. It gets inserted as a normal `components` row with `is_primary = true`.
This is load-bearing: CycloneDX dependency graphs are almost always rooted at the primary
component's `bom-ref`, so skipping the insert dangles every root edge and the
transitive-dependents walk loses its top.

There is deliberately **no** `documents.primary_component_id`. Pointing documents at
components while components point back at documents is a circular FK, and DuckDB's FK
support is limited (no cascade, restricted updates). The `is_primary` flag does the same
job with no cycle.

`bom-ref` is optional in the spec, so a missing one is synthesized (`synthetic:<n>`) to keep
`UNIQUE (document_id, bom_ref)` satisfiable.

`parent_component_id` preserves nested `components[].components`, which CycloneDX permits to
arbitrary depth. One nullable column keeps the nesting rather than silently flattening it.

### Derived package identity (`package_key`)

Computed at ingest, since purl is optional:

- purl present: normalized purl with qualifiers and subpath stripped, version kept.
  `pkg:npm/Foo@1.2.3?arch=x64` becomes `pkg:npm/foo@1.2.3`.
- purl absent: `generic:{group}/{name}@{version}`, empty segments collapsed.

Two components collapse to one package only if their `package_key` matches. Deliberately
conservative: a missing purl never merges with a present one.

Note this table is really *package-version*, not package. A component named `packages`
holding a version column is a naming compromise; the scaling section should call out that a
real system separates `package` from `package_version`.

Case handling is narrow on purpose: purl `type` and `namespace` lowercase safely, but `name`
case sensitivity is ecosystem-dependent, and lowercasing wholesale would merge distinct
Maven artifacts. Lowercase type and namespace only, and document the residual risk.

### Licenses

CycloneDX allows three shapes: `{license:{id}}`, `{license:{name}}`, and
`{expression: "MIT OR Apache-2.0"}`. Expressions are tokenized at ingest into one
`component_licenses` row **per extracted SPDX id**, with the original expression preserved on
the join row. That is what makes `--license MIT` match a component declared
`MIT OR Apache-2.0`. Tokenization is deliberately naive: split on `OR`, `AND`, `WITH`, and
parens.

`raw_expression` and `declared_source` live on `component_licenses`, not on `licenses`,
because the expression is a property of how *this component* declared its license, not of
the license itself.

`licenses.license_key` is a single derived, non-null column (`spdx:mit`, `name:some custom
license`) rather than a natural key over three nullable columns. SQL treats NULLs as distinct
in UNIQUE constraints, so a three-nullable-column key would not deduplicate at all.

### Dependencies

Per-document, because the same package resolves to different dependencies in different
applications. Refs pointing at a `bom-ref` absent from the document are skipped, with a
count reported at the end of ingest rather than a hard failure.

### Document identity and re-ingest

`serialNumber` is optional, and both syft and cdxgen generate a **new** UUID every run while
leaving `version` at 1. Keying on `(serial_number, version)` alone would mean a regenerated
SBOM of the same software looks like an entirely new document, and the revision history would
only ever fire on hand-crafted fixtures.

**Decided:** `document_key = COALESCE(serial_number, 'sha256:' || content_hash)`, with
`content_hash` always stored. Re-ingesting a byte-identical file is a no-op, which is the
honest dedupe. `serial_number` and `version` stay as recorded metadata, so the
`latest_documents` view still works where publishers do maintain serial numbers across
revisions.

```sql
CREATE VIEW latest_documents AS
  SELECT * FROM documents d
  WHERE d.serial_number IS NULL
     OR d.version = (
       SELECT MAX(version) FROM documents
       WHERE serial_number = d.serial_number
     );
```

The richer drift model groups snapshots by *subject* (primary component name and version) on
an `ingested_at` timeline, since that survives regeneration. Deferred, not built.

DESIGN.md should say plainly that CycloneDX revision history is a modeling choice the
generated fixtures do not exercise.

## Query Semantics

```
sbom-cli ingest <sbom-file>
sbom-cli query --component <name> [--version <version>]
sbom-cli query --license <license>
```

`--component` returns, for each match:

1. the documents that contain it, and
2. the ancestor components within each document that transitively depend on it.

That second half is the answer to "documents **or packages**": a transitive-dependents walk
via recursive CTE over `dependencies`. Without it the query answers half the prompt.

**The recursive CTE needs a cycle guard.** Real dependency graphs occasionally contain
cycles; `UNION ALL` with no guard hangs. Use `UNION` to dedupe intermediate rows *and* cap
depth, and keep one cyclic fixture to prove it terminates.

### Matching rules

Written down because streams 4 and 5 would otherwise guess differently:

- `--component <name>`: exact match, case-insensitive.
- `--version`: exact match, case-sensitive (version strings are opaque; no semver ranges).
- purl is **not** searched by `--component`. A separate `--purl` flag is the clean way to add
  that, deferred.
- `--license`: exact match against extracted SPDX ids, case-insensitive.
- `--component` and `--license` together: rejected with a usage error rather than silently
  ANDed or ORed. Combining them is a reasonable feature, but guessing the semantics is worse
  than declining.
- Database location: `--db` flag, defaulting to `./sbom.duckdb`.

Output defaults to a human-readable table, with `--json` for machine consumption. Exit 0 on a
successful query regardless of hit count.

`ComponentHit.Dependents` renders as flat `name@version` strings, which loses hop depth.
Acceptable for the hour; worth noting as a limitation.

## Example Data

Roughly 10 CycloneDX 1.6 JSON SBOMs, mixed provenance:

- ~8 hand-crafted with deliberately overlapping components, shared licenses, real transitive
  depth, at least one license expression, at least one component with no purl, at least one
  nested sub-component, and one cyclic graph.
- 1-2 generated with `syft` or `cdxgen` against a real project, to prove the parser survives
  real-world output.

The hand-crafted set has to carry the edge cases. Generated SBOMs are well-formed and
uniform, so they exercise volume, not variety.

## Ingest strategy

The plan originally assumed SQL-first ingest via DuckDB's `read_json`, on the theory that it
would keep Go thin. **Decided: parse in Go with `cyclonedx-go` instead.** Reasons:

- `cyclonedx-go` already models 1.6, including the license choice union and nested
  `components[].components`. Arbitrarily-nested arrays need recursive JSON unnesting to
  flatten in SQL, which is genuinely painful.
- SQL-first was simultaneously the plan's top named risk *and* the only justification for
  dropping unit tests. Bad combination for a load-bearing decision.
- `package_key` and license tokenization become ordinary pure functions.

Cost is more Go code, but it is mechanical code with no unknowns. DuckDB remains the store;
it just gets rows via batched inserts rather than reading JSON itself. The spike is gone, so
there is no longer a top-risk item in this plan.

## Work Streams

Parallelizable, with dependency order noted.

| # | Stream | Depends on | Notes |
|---|--------|-----------|-------|
| 0 | CGO build warm-up | none | Launch first, background. Throwaway `main.go` that opens an in-memory DuckDB and runs `SELECT 1`, then `go build`. Proves the driver compiles and warms the build cache |
| 1 | Sample SBOM fixtures | none | Craft the overlap graph and edge cases on purpose; generate the real ones last |
| 2 | Schema DDL + DB open/init | none | Embedded SQL, idempotent init |
| 3 | Ingest: parse, normalize, batch insert | 2 | `package_key` and license tokenization as pure functions |
| 4 | Query: component (recursive CTE, cycle-guarded) and license | 2 | Can be written against hand-inserted rows before 3 lands |
| 5 | Cobra CLI + table/JSON rendering | none | Codes against the `store.Store` interface |
| 6 | README + design doc | 1-5 | README must mention the CGO requirement |

Stream 0 launches first and runs in the background; nothing waits on it, but everything
waits on it *implicitly* at the first real build, so starting it late just moves the cost.
Streams 1, 2, and 5 then start cold and in parallel. 3 and 4 both unblock on 2 and are
independent of each other. Every decision is now settled, so nothing is gated on a question.

If stream 0 fails outright, that is the only genuine stop-the-world event in this plan:
DuckDB is unusable and the fallback is SQLite via `modernc.org/sqlite` (pure Go, no CGO).
The schema is portable; the recursive CTE and `COALESCE` logic both work in SQLite. Better to
discover that at minute 1 than minute 20.

The `store.Store` interface and result types are already settled in
`internal/store/types.go`, which is what streams 4 and 5 most needed to agree on.

## Triage: the 60-Minute Budget

### Priority tiers

| Tier | Scope | Rationale |
|------|-------|-----------|
| **T0** must ship | ingest; `query --component` (+`--version`); `query --license`; README | The literal brief. Missing any of these is a failed submission. |
| **T1** the differentiators | transitive-dependents walk; canonical `packages`; license expression tokenization; content-hash dedupe | Where the design judgment actually shows. Worth more than T2+T3 combined. |
| **T2** polish | `--json` output; `latest_documents` view; nested sub-components; cyclic fixture; unit tests on the pure functions | Cheap individually, none load-bearing. |
| **T3** cut first | multi-path ingest; `--purl`; `--all-versions`; integration tests | Already in Deferred. Do not start these. |

### Wall clock

Assumes subagent fan-out, so parallel streams overlap.

| Time | Foreground | In parallel (subagents) |
|------|-----------|------------------------|
| 0 | Kick off **stream 0** first, before anything else | **Stream 0: CGO build warm-up** |
| 0-5 | `go mod tidy` with `cyclonedx-go`; schema DDL | Fixtures (stream 1); Cobra skeleton (stream 5); DESIGN.md draft |
| 5-20 | Ingest: parse, normalize, batch insert | fixtures land; CLI skeleton lands |
| 20-30 | `query --component`, documents only | — |
| 30-40 | `query --license` with expression tokenization | — |
| 40-50 | Transitive-dependents recursive CTE | — |
| 50-60 | README, DESIGN.md reconciliation, final commits | — |

**First demoable point is minute 30**: ingest plus `--component` returning documents. That is
the literal brief satisfied. Everything after 30 is upside.

DESIGN.md drafts from minute 0 in parallel, because `PROMPT.md` already contains nearly all
of its content and only needs restructuring plus actuals. That takes the largest
non-code deliverable off the critical path.

### Decision gates

- **Minute 20, ingest not writing rows:** drop canonical `packages`. Denormalize
  name/version/purl onto `components` and move on. Costs a T1 item, unblocks all of T0.
- **Minute 30, no query returning rows:** ship `--component` only, cut `--license`. One
  working query beats two broken ones.
- **Minute 45, hard stop on feature work.** Whatever state the code is in, start docs.
- **Minute 50 is not negotiable.** A partial CLI with a clear README is a valid submission;
  a working CLI with no README misses a stated deliverable.

### Cut order, when time runs short

Cut from the bottom: `--json` → nested sub-components → `latest_documents` view →
cyclic fixture → unit tests → transitive dependents → canonical packages.

Transitive dependents and canonical packages are last to cut, ahead of every T2 item,
because they are the only parts of this plan that answer the "or packages" half of the
prompt and the scaling question. Losing them turns a considered submission into a
CRUD exercise.

## Testing Tradeoff

No TDD on this exercise; the time box does not allow it.

Approach: build it, then verify by running the real CLI against the fixture SBOMs and
checking output by hand. Because ingest parses in Go, `package_key` and license tokenization
are pure functions and cheap to cover, so they get unit tests first if any time remains.
Query semantics get integration tests over fixtures if more time remains.

A deliberate deviation from the usual red-green-refactor discipline, and it belongs in the
design doc's limitations section.

## Deliverables

1. Git repo with source plus a 1-2 paragraph README on CLI usage. Local commits only for now;
   the public remote gets decided at the end so the clock stays on code.
2. `DESIGN.md` in-repo as the source of truth, pasted into a Google Doc for submission.
   Covers:
   - Design decisions (CLI design, database choice, tradeoffs)
   - Scaling to thousands of SBOMs and millions of components
   - Limitations imposed by the 1-hour box
   - How AI tools were used, successful and unsuccessful

This is an internal role transfer and the interview is largely a formality, so the AI-usage
section gets written from memory at the end. Not curating prompt history as we go.

## Known Limitations (for DESIGN.md)

- CycloneDX revision history is modeled but not exercised by generated SBOMs.
- `packages` is really package-version; a real system separates the two.
- purl name-case is left alone to avoid merging distinct Maven artifacts, so
  case-variant duplicates of the same artifact will not merge.
- `Dependents` loses hop depth.
- No SPDX 3.0 support; CycloneDX 1.6 only.
- License expression tokenization ignores operator semantics, so `--license MIT` matches
  `MIT OR Apache-2.0` even though the component may not actually be under MIT.

## Deferred

- Public remote: account and repo name, decided after the code is done.
- `--all-versions` on queries.
- `--purl` query flag.
- Combining `--component` and `--license`.
- Ingesting a directory or multiple paths in one invocation.
- Subject-keyed drift timeline, grouping snapshots by primary component name and version.
