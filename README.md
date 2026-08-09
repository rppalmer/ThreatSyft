# ThreatSyft

ThreatSyft is a console-first Python security sidekick. It exposes focused tools through local MCP servers so an AI client, such as VS Code with MCP support, can request structured security context without getting unsafe general-purpose access to the machine.

The current implementation has an enrichment server for indicator context and a knowledge server for defensive ATT&CK, D3FEND, CVE, KEV, and LOLBAS context, plus local IOC extraction. Both keep core logic separate from the MCP transport layer.

Public threat-report discovery, article fetching, and summarisation are deliberately **not** here. They belong to the separate net-razor project, which already owns retrieving content it did not author. ThreatSyft never fetches a URL you hand it; `extract_iocs` works on text you already have.

## What It Does

ThreatSyft helps enrich IP addresses, domains, URLs, and file hashes with common security investigation context:

- DNS records for a domain
- RDAP registration data for a domain or IP address
- WHOIS information for a domain or IP address
- IP geolocation details
- AbuseIPDB IP reputation
- GreyNoise IP context
- VirusTotal IP reports
- VirusTotal domain reports
- VirusTotal URL reports
- VirusTotal file hash reports
- SecurityTrails domain intelligence
- Shodan passive host information
- AlienVault OTX indicator context
- Google Safe Browsing URL checks
- Single-call enrichment across every source supporting an indicator type
- Local MITRE ATT&CK Enterprise technique lookup
- Local MITRE ATT&CK Enterprise technique search
- Local MITRE ATT&CK Enterprise tactic lookup
- Local MITRE D3FEND defensive technique lookup
- Local MITRE D3FEND defensive technique search
- Local ATT&CK-to-D3FEND defensive mapping
- Aggregate ATT&CK technique knowledge briefs
- Targeted NVD CVE lookups
- Aggregate vulnerability knowledge briefs
- Local CISA KEV CVE lookup
- Local CISA KEV search
- Local LOLBAS defensive living-off-the-land lookup
- Local LOLBAS search
- Local knowledge snapshot status checks
- Explicit knowledge snapshot updates from `threatsyft-update`
- Local IOC extraction from text

Each tool has one explicit job and returns a structured JSON response with a stable envelope:

```json
{
  "ok": true,
  "tool": "dns_lookup",
  "query": {},
  "data": {},
  "error": null
}
```

Errors use the same shape, which makes results easier for humans and AI clients to inspect:

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

## MCP Servers

The enrichment MCP server is defined in `src/threatsyft/mcp/enrichment_server.py`.

It exposes focused read-only tools:

- `enrichment_status()`
- `dns_lookup(domain: str)`
- `rdap_lookup(target: str)`
- `whois_lookup(target: str)`
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
- `enrich(indicator: str)`

The knowledge MCP server is defined in `src/threatsyft/mcp/knowledge_server.py`.

It exposes defensive knowledge tools:

- `attack_technique_lookup(technique_id: str)`
- `attack_search(query: str, limit: int = 10)`
- `attack_tactic_lookup(tactic: str)`
- `d3fend_lookup(defense_id_or_name: str)`
- `d3fend_search(query: str, limit: int = 10)`
- `attack_defense_mapping(technique_id: str)`
- `technique_brief(technique_id: str)`
- `cve_lookup(cve_id: str)`
- `vulnerability_brief(cve_id: str)`
- `kev_lookup(cve_id: str)`
- `kev_search(query: str, limit: int = 10)`
- `lolbas_lookup(name: str)`
- `lolbas_search(query: str, limit: int = 10)`
- `extract_iocs(text: str)`
- `knowledge_status()`

Each MCP server is a plain stdio server. After installing the package, start them with stable console commands:

```bash
threatsyft-enrichment-mcp
threatsyft-knowledge-mcp
```

For repository-local development, VS Code also includes `.vscode/mcp.json` entries that start the same servers from the project virtual environment:

```bash
.venv/bin/python -m threatsyft.mcp.enrichment_server
.venv/bin/python -m threatsyft.mcp.knowledge_server
```

The MCP layers are deliberately thin. They register tools and pass requests to core modules. Enrichment logic lives under `src/threatsyft/enrichment/` and knowledge logic lives under `src/threatsyft/knowledge/`.

## Tool Overview

### `enrichment_status()`

Checks local enrichment provider configuration without calling external providers.

Returned data includes provider tool names, API-key presence booleans, the configured and missing key lists across every provider, and `secret_values_returned: false`.

### `dns_lookup(domain: str)`

Looks up common DNS records for a domain.

Supported record types:

- `A`
- `AAAA`
- `MX`
- `NS`
- `TXT`

The input must be a domain name, not a URL. For example, use `example.com`, not `https://example.com`.

### `rdap_lookup(target: str)`

Looks up compact RDAP details for a domain or IP address.

Returned data includes fields such as:

- target type
- handle
- name
- country
- status
- entities
- nameservers
- events
- source URL

### `whois_lookup(target: str)`

Looks up WHOIS information for a domain or IP address.

Domain lookups use `python-whois`. IP lookups use `ipwhois` with a certifi-backed HTTPS opener so RDAP-based IP WHOIS works reliably on macOS Python environments.

### `abuseipdb_check_ip(ip: str, max_age_days: int = 90)`

Checks AbuseIPDB reputation for one IP address.

Returned data may include:

- abuse confidence score
- report count
- distinct reporter count
- country and ISP context
- Tor and whitelist flags
- last reported timestamp
- a light verdict

### `greynoise_ip_context(ip: str)`

Checks GreyNoise context for one IP address.

Returned data may include:

- whether the IP is observed as internet noise
- whether the IP is part of RIOT/business-service data
- provider classification
- name
- last seen timestamp
- provider link
- a light verdict

### `virustotal_ip_report(ip: str)`

Fetches a compact VirusTotal report for one IP address.

Returned data may include:

- ASN and owner
- country and network context
- reputation
- last analysis stats
- total community votes
- tags
- provider link
- a light verdict

### `virustotal_domain_report(domain: str)`

Fetches a compact VirusTotal report for one domain.

Returned data may include:

- reputation
- registrar
- creation and WHOIS dates
- last analysis stats
- recent DNS records
- categories
- community votes
- tags
- provider link
- a light verdict

### `virustotal_url_report(url: str)`

Fetches a compact VirusTotal report for one URL.

Returned data may include:

- final URL
- title
- reputation
- last analysis stats
- categories
- community votes
- first and last submission dates
- last HTTP response code
- provider link
- a light verdict

### `virustotal_file_report(file_hash: str)`

Fetches a compact VirusTotal report for one MD5, SHA1, or SHA256 file hash.

Returned data may include:

- MD5, SHA1, and SHA256 values
- meaningful file name
- file names
- file type and size
- reputation
- last analysis stats
- signature info
- tags
- provider link
- a light verdict

### `securitytrails_domain_lookup(domain: str)`

Fetches compact SecurityTrails domain intelligence for one domain.

Returned data may include:

- hostname and apex domain
- Alexa rank when available
- current DNS records
- compact WHOIS fields
- provider link

### `shodan_host_lookup(ip: str)`

Fetches passive Shodan host information for one IP address.

Returned data may include:

- organization, ISP, and ASN
- country, region, and city
- hostnames and domains
- observed ports
- observed services
- vulnerabilities reported by Shodan
- last update timestamp
- provider link
- a light verdict

### `ipgeolocation_lookup(ip: str)`

Looks up best-effort IP geolocation details for one IP address using IPGeolocation.io.

Returned data may include:

- country, region, city, and postal code
- latitude and longitude
- time zone
- ASN
- ISP and organization
- provider link
- approximation note

### `alienvault_indicator_lookup(indicator: str)`

Fetches compact AlienVault OTX context for one IP address, domain, URL, or file hash.

Returned data may include:

- indicator type
- pulse count
- compact pulse details
- reputation and validation fields when available
- available OTX sections
- provider link
- a light verdict

### `google_safebrowsing_check_url(url: str)`

Checks one URL against Google Safe Browsing threat lists.

Returned data may include:

- whether the URL matched
- threat list matches
- threat type and platform type
- cache duration
- threat metadata when available
- a light verdict

### `enrich(indicator: str)`

Classifies one indicator and collects context from every source that supports its type, in a single call. Accepts an IP, domain, URL, or MD5/SHA1/SHA256 hash.

This is collection, not judgement. It returns **no** overall verdict and no confidence score: a verdict computed here would silently change meaning when one provider rate-limits, and the caller cannot see that happen. Interpretation is the calling agent's job.

Returned data includes:

- `indicator` and `indicator_type`, echoed back so a caller that guessed wrong can self-correct
- `source_summary`, an `{ok, failed}` count for branching without iterating
- `sources`, one map keyed by source name where every entry has the same shape whether it succeeded (`{"ok": true, "data": {...}}`) or not (`{"ok": false, "code": ..., "message": ...}`)

Source order is fixed and independent of which source responds first.

`ok: false` means only that the caller must change something: unclassifiable input, or a reference that belongs to another tool. Every source failing is still `ok: true` with the failures attributed, because retrying will not fix an absence of data. Passing a CVE or ATT&CK technique id returns `ok: false` naming the tool that does handle it.

### `attack_technique_lookup(technique_id: str)`

Looks up one MITRE ATT&CK Enterprise technique from the local STIX snapshot.

The input must be a technique ID such as `T1059` or `T1059.001`.

Returned data includes fields such as:

- technique ID and name
- tactics
- platforms
- data sources
- detection guidance
- mitigations
- references
- parent and subtechnique relationships
- revoked and deprecated flags

### `attack_search(query: str, limit: int = 10)`

Searches local MITRE ATT&CK Enterprise techniques without using the network.

Returned data includes compact ranked matches with technique ID, name, tactics, platforms, and matched context.

### `attack_tactic_lookup(tactic: str)`

Looks up one MITRE ATT&CK Enterprise tactic from the local STIX snapshot.

The input can be a short name such as `initial-access` or a display name such as `Initial Access`.

Returned data includes tactic metadata and associated techniques.

### `d3fend_lookup(defense_id_or_name: str)`

Looks up one MITRE D3FEND defensive technique from the local snapshot.

The input can be a D3FEND ID such as `D3-FA` or a defensive technique name such as `File Analysis`.

Returned data includes defensive tactic, artifacts, top-level defensive technique grouping, related ATT&CK techniques, synonyms, and source metadata.

### `d3fend_search(query: str, limit: int = 10)`

Searches local MITRE D3FEND defensive techniques without using the network.

Returned data includes compact ranked matches with D3FEND ID, name, defensive tactics, related ATT&CK technique count, and matched context.

### `attack_defense_mapping(technique_id: str)`

Maps one ATT&CK technique ID to related MITRE D3FEND defensive techniques using the local inferred mapping snapshot.

Returned data includes the ATT&CK technique name, defensive technique count, mapped defensive techniques, defensive tactics, and artifacts.

### `technique_brief(technique_id: str)`

Builds a compact deterministic knowledge bundle for one ATT&CK technique.

Returned data includes ATT&CK technique details, D3FEND defensive mappings, related LOLBAS entries, key points, source results, and source errors. It does not write the final investigation narrative; the agent remains responsible for interpretation.

### `cve_lookup(cve_id: str)`

Looks up one CVE using the NVD CVE API.

Unlike the local snapshot tools, this is a live network lookup because a full CVE mirror would be large. It uses `NVD_API_KEY` when configured, but the key is optional.

Returned data includes NVD description, publication dates, status, best available CVSS metric, weaknesses, references, affected CPEs, and CISA fields when NVD provides them.

### `vulnerability_brief(cve_id: str)`

Builds a compact deterministic knowledge bundle for one CVE.

Returned data includes NVD CVE details when available, local CISA KEV details when present, `in_kev`, key points, source results, and source errors. It does not make the final risk decision for the agent.

### `kev_lookup(cve_id: str)`

Looks up one CVE in the local CISA Known Exploited Vulnerabilities catalog.

Returned data includes whether the CVE is in KEV, vendor/project, product, vulnerability name, date added, due date, required action, ransomware campaign flag, CWE values, and source metadata.

### `kev_search(query: str, limit: int = 10)`

Searches the local CISA KEV catalog without using the network.

Returned data includes compact ranked matches with CVE ID, affected vendor/product, vulnerability name, required action, and matched context.

### `lolbas_lookup(name: str)`

Looks up one LOLBAS entry from the local catalog.

Returned data includes defensive context such as categories, ATT&CK technique IDs, paths, detection references, resources, privileges, operating systems, and use cases. Raw command examples are intentionally omitted.

### `lolbas_search(query: str, limit: int = 10)`

Searches the local LOLBAS catalog without using the network.

Returned data includes compact ranked matches with entry name, categories, ATT&CK technique IDs, source URL, and matched context.

### `knowledge_status()`

Checks local knowledge snapshot availability without calling external providers.

Returned data includes snapshot paths, availability, counts, file modified timestamps, source update timestamps when available, setup commands, unavailable snapshot names, and live-tool configuration status for `cve_lookup`. It does not print secret values.

### `extract_iocs(text: str)`

Extracts typed IOC candidates from text you already have. No network access; it does not fetch URLs.

Returned data includes `iocs` (IPs, domains, URLs, file hashes, CVE IDs, values only), `ioc_counts`, and `untrusted_context`. It handles common defanged forms such as `hxxp://example[.]com`.

`iocs` carries values only so a caller can iterate it and feed the values straight to an enrichment tool. The surrounding source text stays under `untrusted_context`, keyed by IOC value, and is never merged into a server-authored field — a caller can drop that key entirely without losing any indicator.

## Project Layout

```text
.
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── src/
│   └── threatsyft/
│       ├── config.py
│       ├── enrichment/
│       │   ├── abuseipdb.py
│       │   ├── alienvault.py
│       │   ├── dns.py
│       │   ├── greynoise.py
│       │   ├── ipgeolocation.py
│       │   ├── models.py
│       │   ├── rdap.py
│       │   ├── safebrowsing.py
│       │   ├── securitytrails.py
│       │   ├── shodan.py
│       │   ├── virustotal.py
│       │   └── whois.py
│       ├── knowledge/
│       │   ├── attack.py
│       │   ├── d3fend.py
│       │   ├── iocs.py
│       │   ├── kev.py
│       │   ├── lolbas.py
│       │   └── update_attack.py
│       └── mcp/
│           ├── enrichment_server.py
│           └── knowledge_server.py
└── tests/
```

## Configuration

The current version supports these environment variables:

- `THREATSYFT_TIMEOUT_SECONDS`: network timeout for enrichment calls. Defaults to `15`.
- `THREATSYFT_ATTACK_STIX_PATH`: local MITRE ATT&CK Enterprise STIX cache path. Defaults to `~/.threatsyft/knowledge/attack/enterprise-attack.json`.
- `THREATSYFT_ATTACK_STIX_URL`: source URL used by the explicit ATT&CK update command.
- `THREATSYFT_CISA_KEV_PATH`: local CISA KEV cache path. Defaults to `~/.threatsyft/knowledge/cisa/known_exploited_vulnerabilities.json`.
- `THREATSYFT_CISA_KEV_URL`: source URL used by the explicit CISA KEV update command.
- `THREATSYFT_D3FEND_PATH`: local D3FEND cache path. Defaults to `~/.threatsyft/knowledge/d3fend/d3fend.json`.
- `THREATSYFT_D3FEND_TECHNIQUES_URL`: source URL used by the explicit D3FEND update command.
- `THREATSYFT_D3FEND_TACTICS_URL`: source URL used by the explicit D3FEND update command.
- `THREATSYFT_D3FEND_MAPPINGS_URL`: source URL used by the explicit D3FEND update command.
- `THREATSYFT_NVD_BASE_URL`: base URL for `cve_lookup`. Defaults to `https://services.nvd.nist.gov/rest/json/cves/2.0`.
- `THREATSYFT_LOLBAS_PATH`: local LOLBAS cache path. Defaults to `~/.threatsyft/knowledge/lolbas/lolbas.json`.
- `THREATSYFT_LOLBAS_URL`: source URL used by the explicit LOLBAS update command.
- `ABUSEIPDB_API_KEY`: API key for `abuseipdb_check_ip`.
- `GREYNOISE_API_KEY`: API key for `greynoise_ip_context`.
- `VIRUSTOTAL_API_KEY`: API key for VirusTotal IP, domain, URL, and file reports.
- `SECURITYTRAILS_API_KEY`: API key for `securitytrails_domain_lookup`.
- `SHODAN_API_KEY`: API key for `shodan_host_lookup`.
- `IPGEOLOCATION_API_KEY`: API key for `ipgeolocation_lookup`.
- `ALIENVAULT_API_KEY`: API key for `alienvault_indicator_lookup`.
- `GOOGLE_SAFEBROWSING_API_KEY`: API key for `google_safebrowsing_check_url`.
- `NVD_API_KEY`: optional API key for `cve_lookup`.

Copy `.env.example` to `.env` for local API key setup. Do not commit `.env`.

## Host Compatibility

ThreatSyft works with MCP hosts that can launch local stdio servers. The server code is host-generic; the only host-specific part is the configuration file format.

Install the project in a virtual environment:

```bash
python -m pip install -e .
```

Then configure your MCP host to launch one or more of the console scripts. If the
host does not inherit your shell `PATH`, use the absolute path to the script in
your virtual environment, such as
`/absolute/path/to/.venv/bin/threatsyft-enrichment-mcp`.

LM Studio and Cursor use a Cursor-style `mcp.json` with a top-level
`mcpServers` object:

```json
{
  "mcpServers": {
    "threatsyft-enrichment": {
      "command": "/absolute/path/to/.venv/bin/threatsyft-enrichment-mcp"
    },
    "threatsyft-knowledge": {
      "command": "/absolute/path/to/.venv/bin/threatsyft-knowledge-mcp"
    }
  }
}
```

VS Code uses `.vscode/mcp.json` with a top-level `servers` object:

```json
{
  "servers": {
    "threatsyft-enrichment": {
      "type": "stdio",
      "command": "/absolute/path/to/.venv/bin/threatsyft-enrichment-mcp"
    },
    "threatsyft-knowledge": {
      "type": "stdio",
      "command": "/absolute/path/to/.venv/bin/threatsyft-knowledge-mcp"
    }
  }
}
```

Copy-pasteable examples live under `docs/mcp/`:

- `docs/mcp/lm-studio.example.json`
- `docs/mcp/cursor.example.json`
- `docs/mcp/vscode.example.json`

The repository-local `.vscode/mcp.json` is a development convenience that runs
the same servers through `.venv/bin/python -m ...` with `PYTHONPATH=src`.
Claude Desktop currently emphasizes DXT packaging for local MCP installation, so
this repository does not yet ship a Claude Desktop extension bundle. The console
commands above are the right runtime entry points if you decide to package one
later.

## Development Commands

Install or update dependencies:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
.venv/bin/python -m pytest
```

Run Ruff checks:

```bash
.venv/bin/ruff check .
```

Check formatting:

```bash
.venv/bin/ruff format --check .
```

Refresh a local knowledge snapshot:

```bash
.venv/bin/threatsyft-update attack
.venv/bin/threatsyft-update kev
.venv/bin/threatsyft-update d3fend
.venv/bin/threatsyft-update lolbas
```

Refresh all of them in sequence:

```bash
.venv/bin/threatsyft-update all
```

Snapshot updates use live network access. Knowledge MCP lookups are local-only at runtime. If a snapshot is missing, run the relevant update command once.

`threatsyft-update` is the only CLI ThreatSyft ships. MCP is the interface for everything else: snapshot downloads are the one capability with nowhere else to live, since making them an MCP tool would put a multi-megabyte network write behind a model's decision and break the read-only posture of the servers.

A successful update exits with code `0`. A failure exits with `1` while still printing a structured JSON error.

Safe benign sample indicators for manual checks: IP `8.8.8.8`, domain `example.com`, URL `https://example.com/`, MD5 `d41d8cd98f00b204e9800998ecf8427e`. Sources can disagree; `enrich` reports what each one said and leaves the interpretation to you.

## VS Code Tasks

The repository ships convenience tasks. Open the Command Palette, run `Tasks: Run Task`, and choose one of:

- `Install/update dependencies`
- `Ruff: check`
- `Ruff: format check`
- `Pytest`
- `ThreatSyft: Update knowledge snapshots`

## Example Agent Prompts

Once your MCP host has discovered the servers, drive them from the agent with prompts like:

- `Use ThreatSyft enrichment_status and tell me which providers are configured. Do not print secret values.`
- `Use ThreatSyft enrich on 8.8.8.8. Tell me which sources returned data and which failed.`
- `Use ThreatSyft enrich on example.com and summarize what each source said.`
- `Use ThreatSyft enrich on https://example.com/ and explain any disagreement between sources.`
- `Use ThreatSyft virustotal_file_report on d41d8cd98f00b204e9800998ecf8427e.`
- `Use ThreatSyft attack_technique_lookup on T1059 and explain the defensive context.`
- `Use ThreatSyft technique_brief on T1059 and summarize the key defensive context.`
- `Use ThreatSyft vulnerability_brief on CVE-2024-3400 and summarize the NVD and KEV evidence.`
- `Use ThreatSyft kev_search for MOVEit with a limit of 5.`
- `Use ThreatSyft lolbas_lookup on Certutil.exe and summarize defensive detection ideas.`
- `Use ThreatSyft extract_iocs on this incident note and list the indicators it found.`

Prefer `enrich` for a whole picture of one indicator; reach for a provider-specific tool only when you want to isolate a single vendor's view. Use the ATT&CK, D3FEND, CVE, KEV, and LOLBAS knowledge tools when you need stable defensive context rather than provider reputation. Use `extract_iocs` to pull indicators out of text you already have, then enrich those values.

## Troubleshooting

- `missing_api_key`: the expected variable is absent. Check `.env`, or run `.venv/bin/python main.py --compact doctor` for a local-only key-presence check that does not print secrets.
- `authentication_error`: the key exists but the provider rejected it.
- `rate_limited`: wait, or use a different provider-specific tool. `cve_lookup` uses the live NVD API — set `NVD_API_KEY` in `.env` or retry later.
- Slow RDAP or WHOIS: keep `THREATSYFT_TIMEOUT_SECONDS` at `15`, or temporarily raise it in `.env`.
- `not_found` with a missing snapshot path from an ATT&CK, D3FEND, KEV, or LOLBAS tool: run the matching `threatsyft knowledge-update <source>` (or `all`) once, then retry. Use `knowledge-status` for a local-only readiness check.
- MCP tools not showing in VS Code: restart the MCP servers from the Command Palette and confirm `.vscode/mcp.json` points to `${workspaceFolder}/.venv/bin/python`. For LM Studio or Cursor, confirm the configured command path runs from a terminal.

## Design Principles

ThreatSyft favors:

- clear boundaries between MCP transport and enrichment logic
- explicit tool inputs and outputs
- structured error handling
- minimal dependencies
- readable Python with type hints
- safe, read-only capabilities

It does not expose generic command execution, file modification tools, or broad unsafe machine access.

## Project Direction

For durable design context, see:

- `ARCHITECTURE.md` for MCP server boundaries, long-term architecture, and roadmap.
- `AGENTS.md` for standing instructions to future coding agents.
