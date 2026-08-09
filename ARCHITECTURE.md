# ThreatSyft Architecture

ThreatSyft exposes focused, read-only security capabilities to an AI client through MCP, keeping the investigation logic in ordinary Python modules. MCP is the only interface; the one console command downloads snapshots, which cannot live behind a tool call without breaking the servers' read-only posture.

The goal is to build a practical guided SOC sidekick: an agent can call tools, explain findings, and help prioritize next steps, but the tool layer should stay explicit, predictable, and safe.

## Current Architecture

The current implementation has two MCP servers:

```text
threatsyft-enrichment
threatsyft-knowledge
```

Public reporting discovery, article fetching, and summarisation are out of scope and live in the separate net-razor project. ThreatSyft never retrieves content it was not handed; `extract_iocs` operates on text the caller already has. The boundary is strict in both directions: ThreatSyft never calls net-razor and net-razor never calls ThreatSyft. MCP servers expose capabilities and the *client* composes them.

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
- Single-call enrichment across every source supporting an indicator type
- local enrichment provider status checks

`threatsyft-knowledge` exposes local-only defensive knowledge tools for:

- MITRE ATT&CK Enterprise technique lookup
- MITRE ATT&CK Enterprise technique search
- MITRE ATT&CK Enterprise tactic lookup
- ATT&CK technique knowledge briefs
- targeted NVD CVE lookup
- vulnerability knowledge briefs
- CISA KEV CVE lookup
- CISA KEV search
- LOLBAS defensive living-off-the-land lookup
- LOLBAS search
- local knowledge snapshot status checks

The MCP transport lives in `src/threatsyft/mcp/enrichment_server.py`. It should remain thin: register tools, accept explicit inputs, and delegate to core modules.

The knowledge MCP transport lives in `src/threatsyft/mcp/knowledge_server.py` and follows the same thin wrapper pattern.

Core enrichment logic lives under `src/threatsyft/enrichment/`. Core knowledge logic lives under `src/threatsyft/knowledge/`. These modules should be usable outside MCP, including from tests.

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

ThreatSyft should build toward three focused MCP servers.

### `threatsyft-enrichment`

Answers: what do external sources know about this indicator?

Examples:

- DNS, RDAP, WHOIS, and geolocation
- VirusTotal, AbuseIPDB, Shodan, GreyNoise, SecurityTrails, AlienVault OTX, Google Safe Browsing
- `enrich`, which fans out to every source supporting the indicator's type

### `threatsyft-knowledge`

Answers: what known security concepts, techniques, vulnerabilities, or references apply?

Examples:

- MITRE ATT&CK
- CVEs
- CISA KEV
- LOLBAS and living-off-the-land references
- defensive tradecraft and detection context
- behavior-to-technique mapping


Most runtime knowledge lookups are local-only. `cve_lookup` is intentionally live-network because a full CVE mirror is too large for this simple v1 project. Explicit update commands are responsible for downloading or refreshing local snapshots.

## Boundary Guidance

Keep server boundaries tied to the question each tool answers. Do not add more MCP servers unless a new capability has meaningfully different behavior or maintenance needs.

When adding future capabilities, choose the boundary based on the question the tool answers:

- Indicator facts and provider reputation belong in enrichment.
- Stable references and defensive knowledge belong in knowledge.
- Fresh public reporting and article processing belong in net-razor, not here. General rule: put the capability where the trust class already exists.

The agent is the reasoning layer. MCP tools should provide reliable facts, compact summaries, and safe actions.

Parallel fetch is fine; scoring is not. `enrich` calls many sources at once and reports what each returned, with fixed source ordering. It deliberately produces no overall verdict and no confidence score: such a value silently changes meaning when one provider rate-limits, and the caller cannot see that happen. The agent remains responsible for interpretation, caveats, follow-up questions, and written summaries.

## Safety Posture

ThreatSyft is defensive by default.

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
