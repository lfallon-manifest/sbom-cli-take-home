# Example SBOMs

Eight hand-crafted CycloneDX 1.6 JSON documents plus two tool-generated ones. Every hand-crafted
document has a primary component in `metadata.component`, a `components[]` array, and a
`dependencies[]` graph rooted at the primary's `bom-ref`. Edge cases are spread across files so
that queries produce overlaps and the ingester gets exercised on the awkward shapes.

| File | Primary | serialNumber | Components | Edge cases carried |
|------|---------|--------------|------------|--------------------|
| `web-frontend.cdx.json` | @acme/web-frontend 1.4.0 (npm) | yes, version 1 | 12 | plain `pkg:npm/lodash@4.17.21`; 4-hop chain app > express > body-parser > qs > side-channel; `ms` has no licenses |
| `web-frontend-v2.cdx.json` | @acme/web-frontend 1.4.0 (npm) | SAME as web-frontend, version 2 | 13 | revision: axios bumped 1.6.8 > 1.7.4, dayjs@1.11.10 added |
| `api-service.cdx.json` | github.com/acme/api-service v2.3.0 (golang) | yes, version 1 | 12 | lodash purl with qualifiers and subpath `pkg:npm/lodash@4.17.21?arch=x64#lib/index.js`; `internal-auth-sdk` has NO purl and a name-only license "Custom Proprietary License"; `pkg:generic/openssl@3.0.13`; golang.org/x/crypto@v0.21.0 |
| `batch-processor.cdx.json` | com.acme/batch-processor 3.1.0 (maven) | yes, version 1 | 12 | `jakarta.activation@1.2.2` has NO bom-ref; `jakarta.annotation-api` uses `GPL-2.0-only WITH Classpath-exception-2.0`; log4j-core@2.17.1 |
| `mobile-backend.cdx.json` | @acme/mobile-backend 0.9.3 (npm + golang) | NONE | 13 (+2 nested) | uppercase type purl `pkg:NPM/lodash@4.17.21`; `firebase-admin` nests `@google-cloud/firestore@7.3.0` and `@google-cloud/storage@7.7.0` (children are not in the dependency graph); ISC licenses; golang.org/x/crypto@v0.21.0 |
| `data-pipeline.cdx.json` | acme-data-pipeline 0.4.2 (pypi) | yes, version 1 | 13 | TWO dangling refs: `boto3@1.34.69` dependsOn `botocore@1.34.69` (not a component) and a `dependencies[].ref` of `s3transfer@0.10.1` (not a component); `python-dateutil` has two license entries; `cryptography` uses expression `Apache-2.0 OR BSD-3-Clause`; `boto3` has no licenses |
| `legacy-monolith.cdx.json` | com.acme.legacy/legacy-monolith 7.12.4 (maven + npm + deb) | yes, version 1 | 13 | lodash at the OTHER version 4.17.15; log4j-core@2.17.1; `hibernate-core` LGPL-2.1-or-later; `javassist` three license entries; `dom4j` id plus name-only entry; `jquery-legacy-patches` has NO purl and no licenses; `coreutils` deb purl with GPL-3.0-only |
| `cyclic-graph.cdx.json` | acme-edge-proxy 0.3.0 (cargo) | yes, version 1 | 13 | CYCLE hyper > http > bytes > hyper, reachable from the primary; many `MIT OR Apache-2.0` expressions; `ring` uses `(MIT OR Apache-2.0) AND BSD-3-Clause`; `rustls` three license entries; 5-hop chain through serde |
| `generated-syft-sbom-cli.cdx.json` | this repo's directory (syft 1.27.1) | yes | 29 | real output: has `$schema`, NO `dependencies` key, primary is type `file` with no version, no licenses on any component |
| `generated-cdxgen-sbom-cli.cdx.json` | github.com/lfallon/sbom-cli (cdxgen 11.7.0) | yes | 5 | real output: primary `version` is an empty string, has `annotations`, dependency graph present |

Both generated documents are specVersion 1.6. The syft one was produced with
`syft dir:. --exclude './examples/**' -o cyclonedx-json@1.6`, the cdxgen one with `cdxgen -t go --spec-version 1.6`.
Both reflect go.mod at the moment they were generated and are not regenerated automatically.

## Cross-document overlaps

- `lodash` appears in 5 documents: 4.17.21 in web-frontend, web-frontend-v2, api-service, mobile-backend (three purl spellings that
  should normalize to `pkg:npm/lodash@4.17.21`), and 4.17.15 in legacy-monolith.
- `log4j-core` 2.17.1 and `log4j-api` 2.17.1 appear in batch-processor and legacy-monolith.
- `golang.org/x/crypto` v0.21.0 appears in api-service and mobile-backend.
- `express` 4.19.2, `body-parser` 1.20.2, `qs` 6.11.0 appear in web-frontend and web-frontend-v2.
- `axios` appears at two versions: 1.6.8 (web-frontend) and 1.7.4 (web-frontend-v2).

Licenses used across the set: MIT, Apache-2.0, BSD-3-Clause, ISC, GPL-3.0-only, LGPL-2.1-or-later, MPL-1.1, MPL-2.0,
plus expressions containing OR, AND, and WITH, and one name-only license with no SPDX id.

## Suggested queries

```
sbom-cli query --component lodash                     # 5 docs (4 at 4.17.21, 1 at 4.17.15)
sbom-cli query --component lodash --version 4.17.21   # 4 docs, one hit each, despite three purl spellings
sbom-cli query --component lodash --version 4.17.15   # exactly 1 doc: legacy-monolith
sbom-cli query --component log4j-core                 # 2 docs: batch-processor and legacy-monolith, both 2.17.1
sbom-cli query --component qs                         # 2 docs; dependents chain qs@6.11.0 < body-parser@1.20.2 < express@4.19.2 < web-frontend@1.4.0
sbom-cli query --component hyper                      # cyclic-graph; the dependents walk must terminate despite hyper > http > bytes > hyper
sbom-cli query --component botocore                   # 0 hits; it only exists as a dangling ref in data-pipeline
sbom-cli query --license MIT                          # hits in all 8 hand-crafted docs
sbom-cli query --license Apache-2.0                   # 6 docs; must include components declared via "MIT OR Apache-2.0" style expressions
sbom-cli query --license GPL-3.0-only                 # exactly 1 component: coreutils in legacy-monolith
sbom-cli query --license LGPL-2.1-or-later            # 2 components, both in legacy-monolith: hibernate-core and javassist
sbom-cli query --license ISC                          # 4 components across mobile-backend (3) and cyclic-graph (rustls)
```
