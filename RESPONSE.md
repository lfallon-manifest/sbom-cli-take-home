# sbom-cli: design notes

## Design decisions

I picked Go for two reasons.

It's cross-platform and compiles to a static binary, so eventually I can produce builds for a number of different target platforms without asking anyone to install a runtime first.

It's also what I reach for when I know an agent is writing most of the code. Static types plus a compiler mean the feedback loop is tight: the agent gets a real error with a file and a line in a couple of seconds. In an interpreted language a lot of that same class of mistake survives until something actually executes the branch. Go's test tooling is good as well, though what I got out of it inside the hour was unit tests only.

## Limitations from the one-hour constraint

The biggest one is that I didn't get to do much manual testing and investigation to verify the implementation is correct. That felt acceptable in this case: the application isn't overly complex, and ingest and query both correspond directly to straightforward SQL commands.

## Performance at scale

To get a sense of how this holds up, I wrote a script that generates a synthetic corpus: 2,500 SBOMs with 2.3 million components between them. Writing all of it takes about a second and a half. Querying it is comfortable too. Asking which documents contain a package that appears in hundreds of them, including the walk up the dependency graph, comes back in about a quarter of a second, and a license query returning 134,000 hits takes under half a second.

Ingest is the weak spot. It runs at roughly 1,100 components a second, so loading the whole corpus takes about half an hour. Two straightforward changes would account for most of that.

The first is caching. The lookup that maps a package to its stored identity is currently cached per document, so every document asks the database again about packages it has already seen. Caching it across the whole run instead turns roughly 2.3 million lookups into about 42,500, a factor of fifty, because the corpus only contains that many distinct packages no matter how often they recur across documents.

The second is batching the writes. Every component, license and dependency edge is inserted one row at a time today. Aggregating each document's rows and inserting them in a single operation plays to what the database is actually built for.

## How I used AI tools

I used AI tools to expand on an initial prompt, which did two things. It identified gaps in my initial implementation ideas, and it helped me design a parallelizable set of work streams so I could move through generation and implementation quickly. Overall that was successful.

The less successful part was the initial planning stage. The models want to treat this as a production application, so it takes a little bit of work to constrain the model's scope to something that isn't as rigorously implemented and is more appropriate for a take-home exercise.
