# Demo recording for sbom-cli. Requires https://github.com/charmbracelet/vhs.
#
#   vhs demo.tape        # run from the repo root; writes demo.gif
#
# The hidden setup below rebuilds ./sbom-cli and deletes ./sbom.duckdb so the
# ingest starts from an empty database. Both are gitignored, and the recorded
# ingest recreates the database.

Output "demo.gif"

Set Shell "bash"
Set FontSize 13
Set Padding 20
Set Width 1400
Set Height 560
Set Framerate 24
Set TypingSpeed 35ms

Hide
Type "go build -o sbom-cli . && rm -f sbom.duckdb && clear"
Enter
Wait@5m
Show

# Ingest: ten SBOMs in one invocation, then the same file again to show that
# re-ingest is a no-op.
Type "./sbom-cli ingest examples/*.cdx.json"
Enter
Sleep 5s

Type "./sbom-cli ingest examples/web-frontend.cdx.json"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 750ms

# Query: which documents contain a component, and who pulls it in.
Type "./sbom-cli query --component lodash"
Enter
Sleep 6s

# Pin the version, and note the transitive dependents of the match.
Type "./sbom-cli query --component qs --version 6.11.0"
Enter
Sleep 6s

# Query by declared license instead.
Type "./sbom-cli query --license ISC"
Enter
Sleep 5s

# Same answers, machine-readable.
Type "./sbom-cli --json query --license MPL-2.0"
Enter
Sleep 5s
