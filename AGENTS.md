# Agent Instructions

ThreatSyft is a local Python security sidekick that uses MCP as the agent tool layer. The project favors clear, simple, maintainable Python for a single developer building practical defensive security workflows.

## Read First

- Read `ARCHITECTURE.md` before changing MCP server boundaries, tool design, project structure, or long-term architecture (including the API-backed provider and research roadmap).
- Use `README.md` for the current user-facing overview and development commands.

## Standing Rules

- Keep MCP modules thin. They should register tools and delegate to core Python logic.
- Keep business logic outside MCP transport modules.
- Prefer explicit, single-purpose, read-only tools.
- Return structured JSON with the shared `ok`, `tool`, `query`, `data`, and `error` envelope.
- Never add generic command execution tools.
- Never hardcode API keys, credentials, or machine-specific secrets.
- Use environment variables or ignored local `.env` files for secrets.
- Prefer small provider-specific tools before aggregate tools such as `ip_reputation`.
- Keep tests mocked by default for external providers so normal test runs do not require live network access or API keys.
- Treat attacker techniques, living-off-the-land behavior, and EDR evasion content as defensive knowledge only: understanding, mapping, detection, triage, and mitigation are in scope; offensive automation and bypass generation are out of scope.

## Current Direction

Build toward three focused MCP servers over time:

- `threatsyft-enrichment`: indicator enrichment and vendor API lookups.
- `threatsyft-knowledge`: MITRE ATT&CK, CVEs, CISA KEV, LOLBAS, living-off-the-land, and defensive tradecraft knowledge.
- `threatsyft-research`: current public write-ups, summaries, attack flow extraction, and IOC extraction.

Do not split servers before the behavior justifies it. The current implementation should continue using the existing enrichment server while the project is small.
