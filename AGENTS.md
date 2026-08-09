# Agent Instructions

ThreatSyft is a local Python security sidekick that uses MCP as the agent tool layer. The project favors clear, simple, maintainable Python for a single developer building practical defensive security workflows.

## Read First

- Read `ARCHITECTURE.md` before changing MCP server boundaries, tool design, or project structure. It carries the response contract and the reasoning behind it.
- Read `TODO.md` first if it is present. It is a local, unpublished working file listing outstanding work only. Anything not in it is either done or deliberately not being done.
- Use `README.md` for the current user-facing overview and development commands.

## Standing Rules

- Keep MCP modules thin. They should register tools and delegate to core Python logic.
- Keep business logic outside MCP transport modules.
- Prefer explicit, single-purpose, read-only tools.
- Return structured JSON with the shared `ok`, `tool`, `query`, `data`, and `error` envelope.
- Never add generic command execution tools.
- Never hardcode API keys, credentials, or machine-specific secrets.
- Use environment variables or ignored local `.env` files for secrets.
- Parallel fetch is fine; scoring is not. Collecting from many sources in one call is good design; reducing them to a verdict or confidence score is not, because that number changes meaning when a source fails and the caller cannot see it happen.
- Keep tests mocked by default for external providers so normal test runs do not require live network access or API keys.
- Treat attacker techniques, living-off-the-land behavior, and EDR evasion content as defensive knowledge only: understanding, mapping, detection, triage, and mitigation are in scope; offensive automation and bypass generation are out of scope.

## The Architecture

Two MCP servers, six tools:

- `threatsyft-enrichment` holds every API key: `enrich`, `enrichment_status`.
- `threatsyft-knowledge` holds none: `lookup`, `search`, `extract_iocs`, `knowledge_status`.

The per-source functions behind those tools still exist as ordinary Python and are individually tested. They are not exposed as separate tools, because a smaller surface makes tool selection more reliable. Adding a tool needs a reason that `enrich`, `lookup` or `search` cannot cover.

Public write-ups, article fetching, and summarisation belong to the separate net-razor project, which already carries the trust class for retrieving content it did not author. ThreatSyft never fetches a URL it is handed, and the two projects never call each other.

Do not split servers further before the behaviour justifies it.
