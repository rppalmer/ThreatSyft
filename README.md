# ThreatSyft

ThreatSyft is a console-first Python security sidekick. It exposes focused tools through local MCP servers so an AI client, such as VS Code with MCP support, can request structured security context without getting unsafe general-purpose access to the machine.

The current implementation has an enrichment server for indicator context, a knowledge server for defensive ATT&CK, D3FEND, CVE, KEV, and LOLBAS context, and a research server for public threat-report discovery. All three keep core logic separate from the MCP transport layer.

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
- Aggregate IP reputation fact packs
- Aggregate domain reputation fact packs
- Aggregate URL reputation fact packs
- Aggregate file hash reputation fact packs
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
- Explicit knowledge snapshot updates from the CLI
- Curated public security feed search
- Public article metadata and snippet extraction
- Public article IOC extraction

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
- `ip_reputation(ip: str)`
- `domain_reputation(domain: str)`
- `url_reputation(url: str)`
- `file_reputation(file_hash: str)`

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
- `knowledge_status()`

The research MCP server is defined in `src/threatsyft/mcp/research_server.py`.

It exposes public threat-report research tools:

- `research_feed_search(query: str = "", limit: int = 10, days: int = 14)`
- `research_feed_status()`
- `research_article_summary(url: str)`
- `research_article_iocs(url: str)`
- `research_brief(url: str)`

Each MCP server is a plain stdio server. After installing the package, start them with stable console commands:

```bash
threatsyft-enrichment-mcp
threatsyft-knowledge-mcp
threatsyft-research-mcp
```

For repository-local development, VS Code also includes `.vscode/mcp.json` entries that start the same servers from the project virtual environment:

```bash
.venv/bin/python -m threatsyft.mcp.enrichment_server
.venv/bin/python -m threatsyft.mcp.knowledge_server
.venv/bin/python -m threatsyft.mcp.research_server
```

The MCP layers are deliberately thin. They register tools and pass requests to core modules. Enrichment logic lives under `src/threatsyft/enrichment/`, knowledge logic lives under `src/threatsyft/knowledge/`, and public research logic lives under `src/threatsyft/research/`.

## Tool Overview

### `enrichment_status()`

Checks local enrichment provider configuration without calling external providers.

Returned data includes provider tool names, API-key presence booleans, aggregate fact-pack requirements, and `secret_values_returned: false`.

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

### `ip_reputation(ip: str)`

Builds a deterministic fact pack from the provider-specific IP tools.

This tool does not replace the agent's final analysis. It collects and normalizes provider results so the agent has a compact evidence bundle to summarize.

Returned data includes:

- overall verdict
- confidence
- key signals
- provider results
- provider errors

### `domain_reputation(domain: str)`

Builds a deterministic fact pack from the domain-focused tools.

This tool does not replace the agent's final analysis. It collects and normalizes domain evidence so the agent has a compact bundle to summarize.

Returned data includes:

- overall verdict
- confidence
- key signals
- provider results
- provider errors

### `url_reputation(url: str)`

Builds a deterministic fact pack from the URL-focused provider tools.

This tool does not replace the agent's final analysis. It collects and normalizes URL evidence so the agent has a compact bundle to summarize.

Returned data includes:

- overall verdict
- confidence
- key signals
- provider results
- provider errors

### `file_reputation(file_hash: str)`

Builds a deterministic fact pack from the file-hash provider tools.

This tool does not replace the agent's final analysis. It collects and normalizes file hash evidence so the agent has a compact bundle to summarize.

Returned data includes:

- overall verdict
- confidence
- key signals
- provider results
- provider errors

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

Returned data includes snapshot paths, availability, counts, file modified timestamps, source update timestamps when available, setup commands, unavailable snapshot names, and live-tool configuration status for `cve_lookup`. It does not print secret values and does not report RSS feeds, news sources, or research feed configuration.

### `research_feed_search(query: str = "", limit: int = 10, days: int = 14)`

Searches configured public security RSS feeds using live network calls.

Returned data includes matching feed entries, source URLs, published timestamps when available, short matched context, cautious zero-result interpretation, and per-feed errors when one source fails but another succeeds.

### `research_feed_status()`

Lists configured research RSS or Atom feed URLs without fetching them.

Returned data includes configured feed URLs, feed count, configuration source, and `live_network: false`.

### `research_article_summary(url: str)`

Fetches one public HTTP or HTTPS article URL and returns metadata plus short snippets.

Returned data includes title, description, published timestamp when available, lead snippets, and `full_text_returned: false`. It rejects non-HTTP URLs, localhost, and private or reserved IP-literal hosts.

### `research_article_iocs(url: str)`

Fetches one public HTTP or HTTPS article URL and extracts local IOC candidates.

Returned data includes IPs, domains, URLs, file hashes, CVE IDs, small context snippets, and `full_text_returned: false`. It handles common defanged forms such as `hxxp://example[.]com`.

### `research_brief(url: str)`

Builds a compact deterministic research fact pack for one public article URL.

Returned data includes article metadata, snippets, extracted IOCs, IOC counts, key points, suggested next pivots, workflow guidance, source results, and source errors. Suggested pivots name follow-up tools such as `ip_reputation`, `domain_reputation`, `url_reputation`, `file_reputation`, and `vulnerability_brief`, but the brief does not call those tools automatically. The workflow guidance tells agents not to repeat article summary or IOC extraction for the same URL after a successful brief.

## Project Layout

```text
.
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── src/
│   └── threatsyft/
│       ├── config.py
│       ├── enrichment/
│       │   ├── abuseipdb.py
│       │   ├── alienvault.py
│       │   ├── domain_reputation.py
│       │   ├── dns.py
│       │   ├── file_reputation.py
│       │   ├── greynoise.py
│       │   ├── ip_reputation.py
│       │   ├── ipgeolocation.py
│       │   ├── models.py
│       │   ├── rdap.py
│       │   ├── safebrowsing.py
│       │   ├── securitytrails.py
│       │   ├── shodan.py
│       │   ├── url_reputation.py
│       │   ├── virustotal.py
│       │   └── whois.py
│       ├── knowledge/
│       │   ├── attack.py
│       │   ├── d3fend.py
│       │   ├── kev.py
│       │   ├── lolbas.py
│       │   └── update_attack.py
│       ├── research/
│       │   ├── articles.py
│       │   ├── feeds.py
│       │   └── iocs.py
│       └── mcp/
│           ├── enrichment_server.py
│           ├── knowledge_server.py
│           └── research_server.py
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
- `THREATSYFT_RESEARCH_FEEDS`: comma- or newline-separated public RSS/Atom feed URLs for `research_feed_search`. Defaults to BleepingComputer News and Google Cloud Threat Intelligence.
- `THREATSYFT_RESEARCH_USER_AGENT`: user agent used by research HTTP requests. Defaults to `ThreatSyft/1.0`.
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

For easier feed editing, use a quoted multiline value:

```env
THREATSYFT_RESEARCH_FEEDS="
https://feeds.feedburner.com/TheHackersNews
https://www.recordedfuture.com/category/cyber/feed/
https://www.anomali.com/site/blog-rss
https://www.cisecurity.org/feed/advisories
https://www.cisa.gov/automated-https:indicator-sharing-ais
https://isc.sans.edu/rssfeed_full.xml
"
```

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
    },
    "threatsyft-research": {
      "command": "/absolute/path/to/.venv/bin/threatsyft-research-mcp"
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
    },
    "threatsyft-research": {
      "type": "stdio",
      "command": "/absolute/path/to/.venv/bin/threatsyft-research-mcp"
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

Run the console helper:

```bash
.venv/bin/python main.py domain example.com
```

Download or refresh the local MITRE ATT&CK Enterprise snapshot:

```bash
.venv/bin/python main.py knowledge-update attack
```

Download or refresh the local CISA KEV snapshot:

```bash
.venv/bin/python main.py knowledge-update kev
```

Download or refresh the local D3FEND snapshot:

```bash
.venv/bin/python main.py knowledge-update d3fend
```

Download or refresh the local LOLBAS snapshot:

```bash
.venv/bin/python main.py knowledge-update lolbas
```

Check local knowledge snapshot readiness without calling external providers:

```bash
.venv/bin/python main.py --compact knowledge-status
```

Refresh all local knowledge snapshots in sequence:

```bash
.venv/bin/python main.py knowledge-update all
```

Knowledge update commands use live network access to download snapshots. Knowledge MCP lookups are local-only at runtime. If a snapshot is missing, run the relevant update command once from the repository root.

For a short status view, use `--compact`:

```bash
.venv/bin/python main.py --compact domain example.com
```

Try each supported aggregate command:

```bash
.venv/bin/python main.py --compact ip 8.8.8.8
.venv/bin/python main.py --compact domain example.com
.venv/bin/python main.py --compact url https://example.com/
.venv/bin/python main.py --compact file d41d8cd98f00b204e9800998ecf8427e
```

Leave `--compact` off when you want full provider results:

```bash
.venv/bin/python main.py ip 8.8.8.8
.venv/bin/python main.py domain example.com
.venv/bin/python main.py url https://example.com/
.venv/bin/python main.py file d41d8cd98f00b204e9800998ecf8427e
```

Show CLI help:

```bash
.venv/bin/python main.py --help
.venv/bin/python main.py domain --help
```

Run local-only checks for configuration and available tools:

```bash
.venv/bin/python main.py --compact doctor
.venv/bin/python main.py --compact tools
.venv/bin/python main.py --compact knowledge-status
```

Run live smoke checks against safe sample indicators. This uses provider calls and may consume quota:

```bash
.venv/bin/python main.py --compact smoke
```

A successful result exits with code `0`. A failed lookup or invalid input exits with code `1` while still printing a structured JSON error.

Safe benign sample indicators for smoke testing: IP `8.8.8.8`, domain `example.com`, URL `https://example.com/`, MD5 `d41d8cd98f00b204e9800998ecf8427e`. Provider verdicts can disagree; treat aggregate results as evidence bundles for the agent, not final truth.

## VS Code Tasks

The repository ships convenience tasks that wrap `main.py`. Open the Command Palette, run `Tasks: Run Task`, and choose one of:

- `ThreatSyft: CLI domain example.com`
- `ThreatSyft: CLI help`
- `ThreatSyft: CLI doctor`
- `ThreatSyft: CLI tools`
- `ThreatSyft: CLI smoke safe samples`
- `ThreatSyft: Knowledge status`
- `ThreatSyft: Knowledge update all`

## Example Agent Prompts

Once your MCP host has discovered the servers, drive them from the agent with prompts like:

- `Use ThreatSyft enrichment_status and tell me which providers are configured. Do not print secret values.`
- `Use ThreatSyft ip_reputation on 8.8.8.8. Tell me which providers returned results and which failed.`
- `Use ThreatSyft domain_reputation on example.com and summarize the key signals.`
- `Use ThreatSyft url_reputation on https://example.com/ and explain any provider disagreement.`
- `Use ThreatSyft virustotal_file_report on d41d8cd98f00b204e9800998ecf8427e.`
- `Use ThreatSyft attack_technique_lookup on T1059 and explain the defensive context.`
- `Use ThreatSyft technique_brief on T1059 and summarize the key defensive context.`
- `Use ThreatSyft vulnerability_brief on CVE-2024-3400 and summarize the NVD and KEV evidence.`
- `Use ThreatSyft kev_search for MOVEit with a limit of 5.`
- `Use ThreatSyft lolbas_lookup on Certutil.exe and summarize defensive detection ideas.`
- `Use ThreatSyft research_feed_search for ransomware with a limit of 5.`
- `Use ThreatSyft research_brief on https://example.com/report. Summarize the returned fact pack and do not call the research tools again for that same URL unless I ask you to refresh it.`

Use provider-specific tools when you need raw provider detail or want to isolate one data source. Use the ATT&CK, D3FEND, CVE, KEV, and LOLBAS knowledge tools when you need stable defensive context rather than provider reputation. Use the research tools for recent public reporting context or IOC extraction from a known article URL.

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
