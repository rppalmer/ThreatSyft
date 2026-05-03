# Investigatinator Architecture

Investigatinator is a console-first Python security sidekick. It exposes focused, read-only security capabilities to an AI client through MCP while keeping the actual investigation logic in ordinary Python modules.

The goal is to build a practical guided SOC sidekick: an agent can call tools, explain findings, and help prioritize next steps, but the tool layer should stay explicit, deterministic, and safe.

## Current Architecture

The current implementation has three MCP servers:

```text
investigatinator-enrichment
investigatinator-knowledge
investigatinator-research
```

It exposes read-only enrichment tools for:

- DNS lookup
- RDAP lookup
- WHOIS lookup
- IP geolocation
- AbuseIPDB IP reputation
- GreyNoise IP context
- VirusTotal IP reports
- VirusTotal domain reports
- VirusTotal URL reports
- VirusTotal file hash reports
- SecurityTrails domain intelligence
- Shodan passive host information
- IPGeolocation.io IP geolocation
- AlienVault OTX indicator context
- Google Safe Browsing URL checks
- Aggregate IP reputation fact packs
- Aggregate domain reputation fact packs
- Aggregate URL reputation fact packs
- Aggregate file hash reputation fact packs

`investigatinator-knowledge` exposes local-only defensive knowledge tools for:

- MITRE ATT&CK Enterprise technique lookup
- MITRE ATT&CK Enterprise technique search
- MITRE ATT&CK Enterprise tactic lookup
- MITRE D3FEND defensive technique lookup
- MITRE D3FEND defensive technique search
- ATT&CK-to-D3FEND defensive mapping
- ATT&CK technique knowledge briefs
- targeted NVD CVE lookup
- vulnerability knowledge briefs
- CISA KEV CVE lookup
- CISA KEV search
- LOLBAS defensive living-off-the-land lookup
- LOLBAS search
- local knowledge snapshot status checks

`investigatinator-research` exposes live-network public research tools for:

- curated security feed search
- public article metadata and snippet extraction
- public article IOC extraction
- public article research briefs with suggested pivots

The MCP transport lives in `src/investigatinator/mcp/enrichment_server.py`. It should remain thin: register tools, accept explicit inputs, and delegate to core modules.

The knowledge MCP transport lives in `src/investigatinator/mcp/knowledge_server.py` and follows the same thin wrapper pattern.

The research MCP transport lives in `src/investigatinator/mcp/research_server.py` and follows the same thin wrapper pattern.

Core enrichment logic lives under `src/investigatinator/enrichment/`. Core knowledge logic lives under `src/investigatinator/knowledge/`. Core research logic lives under `src/investigatinator/research/`. These modules should be usable outside MCP, including from tests, future CLI commands, or future aggregate analysis functions.

All tools return the shared JSON envelope:

```json
{
  "ok": true,
  "tool": "dns_lookup",
  "query": {},
  "data": {},
  "error": null
}
```

Errors use the same shape:

```json
{
  "ok": false,
  "tool": "dns_lookup",
  "query": {},
  "data": null,
  "error": {
    "code": "invalid_input",
    "message": "Domain must not be empty.",
    "details": null
  }
}
```

## Long-Term MCP Direction

Investigatinator should build toward three focused MCP servers.

### `investigatinator-enrichment`

Answers: what do external sources know about this indicator?

Examples:

- DNS, RDAP, WHOIS, and geolocation
- VirusTotal, AbuseIPDB, Shodan, GreyNoise, SecurityTrails, AlienVault OTX, Google Safe Browsing
- Aggregate tools such as `ip_reputation`, `domain_reputation`, `url_reputation`, and `file_reputation`

### `investigatinator-knowledge`

Answers: what known security concepts, techniques, vulnerabilities, or references apply?

Examples:

- MITRE ATT&CK
- CVEs
- CISA KEV
- LOLBAS and living-off-the-land references
- defensive tradecraft and detection context
- behavior-to-technique mapping

The current knowledge MVP implements MITRE ATT&CK Enterprise lookups using a local STIX snapshot at `~/.investigatinator/knowledge/attack/enterprise-attack.json` by default, MITRE D3FEND lookups and ATT&CK-to-defense mappings using a local snapshot at `~/.investigatinator/knowledge/d3fend/d3fend.json`, targeted NVD CVE lookups, CISA KEV lookups using a local catalog snapshot at `~/.investigatinator/knowledge/cisa/known_exploited_vulnerabilities.json`, and LOLBAS lookups using a local catalog snapshot at `~/.investigatinator/knowledge/lolbas/lolbas.json`. All four paths can still be overridden with environment variables.

Most runtime knowledge lookups are local-only. `cve_lookup` is intentionally live-network because a full CVE mirror is too large for this simple v1 project. Explicit update commands are responsible for downloading or refreshing local snapshots.

### `investigatinator-research`

Answers: what new public information exists, and what can be safely extracted or summarized from it?

Examples:

- searching recent security write-ups
- summarizing attacks
- extracting IOCs from articles
- mapping write-ups to ATT&CK techniques
- comparing new reporting against curated knowledge

The current research MVP implements curated RSS feed search, public article metadata/snippet extraction, local IOC extraction from public article URLs, and single-article research briefs. It is stateless, does not run JavaScript, does not use a search API, and does not return full article bodies.

A future `research_attack_cluster(article_url)` capability should support open-web discovery for similar public reporting. Curated feeds are useful for v1, but they are not the long-term ceiling because emerging-threat reporting can appear from unpredictable vendors, researchers, CERTs, and niche blogs. Before adding open-web search, add explicit safeguards: search-provider APIs instead of uncontrolled crawling, capped fetch counts, URL safety validation, no JavaScript execution, no paywall or authentication bypass, snippets-only output, source/fetch metadata, prompt-injection-aware handling of page text, and capped or explicit enrichment of extracted IOCs.

## Boundary Guidance

Keep server boundaries tied to the question each tool answers. Do not add more MCP servers unless a new capability has meaningfully different behavior or maintenance needs.

When adding future capabilities, choose the boundary based on the question the tool answers:

- Indicator facts and provider reputation belong in enrichment.
- Stable references and defensive knowledge belong in knowledge.
- Fresh public reporting and article processing belong in research.

The agent is the reasoning layer. MCP tools should provide reliable facts, compact summaries, and safe actions.

Aggregate tools such as `ip_reputation`, `domain_reputation`, `url_reputation`, and `file_reputation` should build deterministic evidence bundles. They should not produce the final human-readable investigation narrative; the agent remains responsible for interpretation, caveats, follow-up questions, and written summaries.

## Safety Posture

Investigatinator is defensive by default.

In scope:

- enrichment
- triage
- technique mapping
- detection-oriented explanation
- mitigation-oriented explanation
- IOC extraction from public reporting
- current vulnerability and KEV context

Out of scope unless deliberately reconsidered:

- generic command execution
- credential handling beyond local API key configuration
- exploit generation
- payload generation
- EDR bypass instructions
- offensive automation
- active scanning or probing
- submitting reports or changing third-party state

Any future active capability should require a separate architecture review and explicit user approval.
