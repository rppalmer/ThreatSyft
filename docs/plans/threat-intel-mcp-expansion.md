# Threat Intel MCP Expansion Plan

This plan records the next API-backed enrichment phase and the long-term MCP direction for ThreatSyft.

## Summary

Keep ThreatSyft as one local MCP server for now and add API-backed, read-only IP enrichment in small chunks. The first implementation slice should add provider-specific tools for AbuseIPDB and GreyNoise.

Long term, build toward three focused MCP servers:

- `threatsyft-enrichment`
- `threatsyft-knowledge`
- `threatsyft-research`

The enrichment, knowledge, and research servers now exist. Do not create additional servers until the behavior and maintenance needs justify it.

## Near-Term Direction

Implemented provider-specific tools:

- `abuseipdb_check_ip(ip: str, max_age_days: int = 90)`
- `greynoise_ip_context(ip: str)`
- `virustotal_ip_report(ip: str)`
- `virustotal_domain_report(domain: str)`
- `virustotal_url_report(url: str)`
- `virustotal_file_report(file_hash: str)`
- `securitytrails_domain_lookup(domain: str)`
- `shodan_host_lookup(ip: str)`
- `ipgeolocation_lookup(ip: str)`
- `alienvault_indicator_lookup(indicator: str)`
- `google_safebrowsing_check_url(url: str)`

Implemented aggregate tools:

- `ip_reputation(ip: str)`
- `domain_reputation(domain: str)`
- `url_reputation(url: str)`
- `file_reputation(file_hash: str)`

Defaults:

- Use `.env` for API keys.
- Keep `.env` ignored by Git.
- Remain stateless for now.
- Return compact normalized summaries.
- Include light labels such as `malicious`, `suspicious`, `benign`, or `unknown` when provider data supports it.
- Make one explicit provider call per tool invocation.
- Use short explicit timeouts.
- Do not add retries, batching, caching, or persistence yet.
- Keep normal tests mocked so they do not require API keys or live network access.

## API Key Handling

Expected environment variables:

- `ABUSEIPDB_API_KEY`
- `GREYNOISE_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `SHODAN_API_KEY`
- `SECURITYTRAILS_API_KEY`
- `IPGEOLOCATION_API_KEY`
- `ALIENVAULT_API_KEY`
- `GOOGLE_SAFEBROWSING_API_KEY`

Rules:

- Never hardcode keys.
- Never return keys in tool output.
- Never log keys.
- Use clear `missing_api_key`, `authentication_error`, and `rate_limited` errors.

## First Provider Tools

### `abuseipdb_check_ip`

Purpose: check AbuseIPDB reputation for one IP address.

Behavior:

- Validate that `ip` is a valid IP address.
- Validate `max_age_days` is within `1..365`.
- Call the AbuseIPDB APIv2 Check endpoint.
- Return a compact summary with fields such as IP, public/routable status, abuse confidence score, total reports, distinct users, country, ISP, usage type, domain, Tor flag, whitelist flag, last reported timestamp, and a light verdict.

### `greynoise_ip_context`

Purpose: check GreyNoise context for one IP address.

Behavior:

- Validate that `ip` is a valid IP address.
- Call the GreyNoise Community API or configured GreyNoise endpoint.
- Return a compact summary with fields such as IP, noise, RIOT, classification, name, last seen, link, message, and a light verdict.
- Treat `noise: true` as scanner/noise context, not automatically malicious unless provider classification supports that.
- Treat RIOT/business-service results as benign context, not proof of safety.

## Later Provider Roadmap

Add provider-specific tools in small groups when they clearly improve coverage.

Avoid new aggregate tools until the provider-specific tools they depend on are stable and tested.

## Future Aggregate Tools

Later, add higher-level tools only when they clearly improve agent workflow.

Aggregate tools should not duplicate provider logic. They should call the same core functions used by the provider-specific MCP tools.
They should return deterministic evidence bundles, not final AI-written investigation narratives.

## Long-Term MCP Servers

### Enrichment

`threatsyft-enrichment` answers: what do external sources know about this indicator?

This server owns:

- DNS, RDAP, WHOIS, and geolocation
- vendor reputation APIs
- future aggregate indicator reputation tools

### Knowledge

`threatsyft-knowledge` answers: what known security concepts, techniques, vulnerabilities, or references apply?

Current implementation:

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
- Most runtime lookups use local snapshots and do not call the network
- `cve_lookup` uses the live NVD CVE API because a full CVE mirror is too large for v1

This server should eventually own:

- MITRE ATT&CK
- CVE lookup
- CISA KEV lookup
- LOLBAS and living-off-the-land references
- defensive tradecraft and detection context
- behavior-to-technique mapping

### Research

`threatsyft-research` answers: what new public information exists, and what can be safely extracted or summarized from it?

Current implementation:

- curated public security RSS feed search
- public article metadata and snippet extraction
- public article IOC extraction
- single-article research briefs with suggested pivots
- stateless live-network fetches
- snippets-only article context, not full article bodies

This server should eventually own:

- searching recent security write-ups
- summarizing attacks
- extracting IOCs from public articles
- mapping write-ups to ATT&CK techniques
- comparing new reporting against curated knowledge
- open-web related-article discovery for emerging threats

Future `research_attack_cluster(article_url)` direction:

- Start from one article URL and discover other public articles describing a similar attack.
- Use open-web search because emerging-threat reporting can appear outside curated feeds.
- Aggregate and deduplicate IOCs across the related article set.
- Optionally enrich a capped set of IOCs only when explicitly designed to avoid surprise quota usage.
- Return a structured evidence bundle, not an AI-written final report.
- Mitigate risk with search-provider APIs, capped result and fetch counts, URL safety validation, no JavaScript execution, no paywall/auth bypass, snippets-only output, source metadata, and prompt-injection-aware treatment of webpage text.

## Testing Plan

For AbuseIPDB:

- Missing API key returns `missing_api_key`.
- Invalid IP returns `invalid_input`.
- Invalid `max_age_days` returns `invalid_input`.
- Successful response returns compact normalized data.
- `401` or `403` returns `authentication_error`.
- `429` returns `rate_limited`.
- Timeout returns `timeout`.
- Malformed JSON returns `parse_error`.

For GreyNoise:

- Invalid IP returns `invalid_input`.
- Missing API key behavior is explicit and tested.
- Successful response normalizes `noise`, `riot`, classification, and message fields.
- `401` or `403` returns `authentication_error`.
- `429` returns `rate_limited`.
- Timeout returns `timeout`.
- Malformed JSON returns `parse_error`.

For MCP:

- The enrichment server registers the existing tools plus new provider-specific tools.
- MCP calls return the same structured envelope as direct Python calls.

## Safety Boundaries

The project is a defensive sidekick.

Allowed:

- enrichment
- triage
- IOC extraction
- technique mapping
- defensive explanations
- detection and mitigation guidance

Not allowed in this plan:

- generic command execution
- active scanning
- exploit or payload generation
- EDR bypass generation
- offensive automation
- third-party reporting or state-changing API calls

## Assumptions

- This remains a personal local tool.
- API-backed lookups are read-only.
- Tool results should be compact enough for an agent to use without flooding context.
- The agent should be guided and explanatory, while the tool layer remains explicit and predictable.
