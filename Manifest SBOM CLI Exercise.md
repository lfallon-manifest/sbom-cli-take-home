# Take-Home Exercise: SBOM CLI

## Background

Your team maintains a library of **Software Bill of Materials (SBOMs)** from various applications. Each SBOM lists software components, versions, and licenses. You are asked to build a simple **CLI tool** (in the language of your choice) that:

1. **Ingests SBOMs** into a database.
2. **Allows queries** to find documents or packages containing a specific component (optionally filtered by version) or a specific license.

**Time Expectation:** Please spend **about 1 hour** on this exercise. Focus on demonstrating your design and implementation approach rather than building production-ready software.

## Requirements

### CLI Functionality

#### Ingest SBOM

```
sbom-cli ingest <sbom-file>
```

- Parse a JSON SBOM (CycloneDX 1.6 or SPDX 3.0 format is acceptable)
- Store in a local database (any data store of your choosing is fine including in-memory, it doesn't have to be a production-quality database).

#### Query SBOMs

```
sbom-cli query --component <name> [--version <version>]
sbom-cli query --license <license>
```

- Returns all documents or packages that contain the specified component
  - If `--version` is provided, only match that version.
- Returns all documents or packages that contain the specified license

### Additional Instructions

If you finish the core functionality early:

- You are **encouraged to add extra functionality or improvements**

If you run out of time:

- **Briefly describe** in your design document what additional features or improvements you would have implemented with more time.

### Deliverables

1. **Link to a public Github repo containing**
   a. Source code
   b. README (~1–2 paragraphs) explaining how to use the CLI
2. **Google doc** containing information about:
   - Design decisions (CLI design, database choice, tradeoffs)
   - How you would scale this for **thousands of SBOMs with millions of components**
   - Any limitations imposed by the 1-hour time constraint
   - How AI tools were used, including successful and unsuccessful usage
     i. Not required but you're welcome to save the prompt history for further discussion.
