# ThreatSyft

ThreatSyft exposes focused security tools through local MCP servers, so an AI client such as VS Code can request structured security context without getting unsafe general-purpose access to the machine. MCP is the only interface; the single console command exists to download snapshots.

The current implementation has an enrichment server for indicator context and a knowledge server for defensive ATT&CK, CVE, KEV, and LOLBAS context, plus local IOC extraction. Both keep core logic separate from the MCP transport layer.

Public threat-report discovery, article fetching, and summarisation are deliberately **not** here. They belong to the separate net-razor project, which already owns retrieving content it did not author. ThreatSyft never fetches a URL you hand it; `extract_iocs` works on text you already have.

## What It Does

ThreatSyft helps enrich IP addresses, domains, URLs, and file hashes with common security investigation context:

- DNS records for a domain
- RDAP registration data for a domain or IP address
- WHOIS information for a domain or IP address
- IP geolocation and ASN from a local MaxMind GeoLite2 database, with the build
  date and age of that database on every answer
- AbuseIPDB IP reputation
- GreyNoise IP context
- Sentinel anonymization context: VPN, proxy, Tor, and datacenter signals, with
  the network the address belongs to
- VirusTotal IP reports
- VirusTotal domain reports
- VirusTotal URL reports
- VirusTotal file hash reports
- SecurityTrails domain intelligence
- Shodan passive host information
- Censys host detail: observed services with the software behind each open port
- AlienVault OTX indicator context
- Google Safe Browsing URL checks
- urlscan.io scan history: where a URL finally lands after redirects, the page
  title, and the host that served it. Reads existing scans; never submits one
- Hybrid Analysis sandbox reports for a file hash: what the sample did when it
  ran, including the ATT&CK technique IDs the behaviour mapped to, which
  `lookup` then resolves locally. Reads existing reports; never detonates
- Single-call enrichment across every source supporting an indicator type
- Local MITRE ATT&CK Enterprise technique lookup
- Local MITRE ATT&CK Enterprise technique search
- Local MITRE ATT&CK Enterprise tactic lookup
- Local MITRE ATT&CK Enterprise software lookup, listing the actors that use it
- Threat actor records listing the malware and tooling ATT&CK records them using
- Targeted NVD CVE lookups
- Single-call reference lookup across ATT&CK, KEV, LOLBAS, and NVD
- Grouped search across ATT&CK, KEV, and LOLBAS
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
  "tool": "enrich",
  "query": {},
  "data": {},
  "error": null
}
```

Errors use the same shape, which makes results easier for humans and AI clients to inspect:

```json
{
  "ok": false,
  "tool": "enrich",
  "query": {},
  "data": null,
  "error": {
    "code": "invalid_input",
    "message": "Indicator must be an IP address, domain, URL, or MD5/SHA1/SHA256 hash.",
    "details": null
  }
}
```

## MCP Servers

The enrichment MCP server is defined in `src/threatsyft/mcp/enrichment_server.py`.

It exposes two tools:

- `enrich(indicator: str)`
- `enrichment_status()`

The knowledge MCP server is defined in `src/threatsyft/mcp/knowledge_server.py`.

It exposes defensive knowledge tools:

- `lookup(reference: str)`
- `search(query: str, source: str = "all", limit: int = 10)`
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

Returned data includes, per provider, its API-key presence booleans and which indicator types `enrich` will call it for; the keyless sources; the configured and missing key lists; and `secret_values_returned: false`. The indicator types are derived from the dispatch table rather than restated, so they cannot report coverage `enrich` no longer has.

### `enrich(indicator: str)`

Classifies one indicator and collects context from every source that supports its type, in a single call. Accepts an IP, domain, URL, or MD5/SHA1/SHA256 hash.

This is collection, not judgement. It returns **no** verdict and no confidence score, per source or overall: a verdict computed here would silently change meaning when one provider rate-limits, and the caller cannot see that happen. Each provider's own fields come back under that provider's own names — `last_analysis_stats`, `abuse_confidence_score`, `classification`, `matched` — and nothing reduces them. Interpretation is the calling agent's job.

Returned data includes:

- `indicator` and `indicator_type`, echoed back so a caller that guessed wrong can self-correct
- `source_summary`, an `{ok, failed}` count for branching without iterating
- `sources`, one map keyed by source name where every entry has the same shape whether it succeeded (`{"ok": true, "data": {...}}`) or not (`{"ok": false, "code": ..., "message": ...}`)
- `warnings`, a list that is empty on a healthy install and carries one line per stale local snapshot, naming its age and the `threatsyft-update` command that fixes it

Source order is fixed and independent of which source responds first.

`ok: false` means only that the caller must change something: unclassifiable input, or a reference that belongs to another tool. Every source failing is still `ok: true` with the failures attributed, because retrying will not fix an absence of data. Passing a CVE or ATT&CK technique id returns `ok: false` naming the tool that does handle it.

### `lookup(reference: str)`

Collects every local source covering one reference, in a single call. Accepts:

- a CVE id such as `CVE-2024-3400`, which asks NVD (live) and the local KEV catalog
- an ATT&CK technique id such as `T1059` or `T1059.001`, which asks ATT&CK and searches LOLBAS
- an ATT&CK tactic id such as `TA0002`
- an ATT&CK mitigation id such as `M1038`
- an ATT&CK group id such as `G0016`, whose record lists the techniques and the
  malware and tooling that group is recorded using
- an ATT&CK software id such as `S0002`, which resolves the malware or tool and
  the groups recorded using it
- a bare name such as `Certutil.exe`, `execution`, `APT29` or `Cozy Bear`

A bare name is ambiguous: it could be a LOLBAS binary, a tactic, or a threat actor or one of its aliases. Rather than guess, `lookup` asks all three. They are local and fast, and the `sources` map shows which one answered.

Returned data includes `reference`, `reference_type`, `source_summary`, the same `sources` map `enrich` returns, and the same `warnings` list.

Each snapshot-backed source carries a `freshness` block with its age and whether it is past its own staleness threshold. Those thresholds are per source, because CISA adds to KEV most weeks while MITRE ships ATT&CK a few times a year: KEV is stale after 14 days, GeoLite2 after 30, ATT&CK and LOLBAS after 180. A snapshot past its threshold is restated in the top-level `warnings` list, because freshness one level inside a source entry is where a reader stops looking.

Passing an IP, URL or file hash returns `ok: false` naming `enrich` instead.

### `search(query: str, source: str = "all", limit: int = 10)`

Searches ATT&CK techniques, ATT&CK threat actors, KEV and LOLBAS by keyword, grouped by source.

Results are never merged into one ranked list. The three catalogs share almost no fields and their scoring functions produce numbers on unrelated scales, so a combined ranking would invent a precision that does not exist.

`limit` applies **per source**, so `source="all"` does not quietly return three times the rows you asked for. Each source reports `match_count` (how many matched in total) alongside `returned` (how many came back), so you can tell 10-of-11 from 10-of-400.

Set `source` to `attack_technique`, `attack_actor`, `kev` or `lolbas` to search just one. These are the same source names `lookup` uses in its `sources` map, so one vocabulary covers both tools.

### `knowledge_status()`

Checks local knowledge snapshot availability without calling external providers.

Returned data includes snapshot paths, availability, counts, file modified timestamps, source update timestamps when available, setup commands, unavailable snapshot names, and live-tool configuration status for the NVD CVE lookup. It does not print secret values.

### `extract_iocs(text: str)`

Extracts typed IOC candidates from text you already have. No network access; it does not fetch URLs.

Returned data includes `iocs` (IPs, domains, URLs, file hashes, CVE IDs, values only), `ioc_counts`, `returned_counts`, `truncated`, `max_items_per_type`, and `untrusted_context`. It handles common defanged forms such as `hxxp://example[.]com`.

`ioc_counts` is how many distinct indicators of each type the text contains, counted before the per-type cap; `returned_counts` is how many came back. They differ exactly for the types listed in `truncated`, so a long report that overflows the cap says so rather than losing indicators silently.

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
│       │   ├── hybrid_analysis.py
│       │   ├── maxmind.py
│       │   ├── models.py
│       │   ├── rdap.py
│       │   ├── safebrowsing.py
│       │   ├── securitytrails.py
│       │   ├── shodan.py
│       │   ├── urlscan.py
│       │   ├── virustotal.py
│       │   └── whois.py
│       ├── knowledge/
│       │   ├── attack.py
│       │   ├── iocs.py
│       │   ├── kev.py
│       │   ├── lolbas.py
│       │   ├── update_attack.py
│       │   └── update_maxmind.py
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
- `THREATSYFT_NVD_BASE_URL`: base URL for the NVD CVE API, which `lookup` calls for a CVE reference. Defaults to `https://services.nvd.nist.gov/rest/json/cves/2.0`.
- `THREATSYFT_LOLBAS_PATH`: local LOLBAS cache path. Defaults to `~/.threatsyft/knowledge/lolbas/lolbas.json`.
- `THREATSYFT_LOLBAS_URL`: source URL used by the explicit LOLBAS update command.
- `ABUSEIPDB_API_KEY`: API key for `abuseipdb_check_ip`.
- `GREYNOISE_API_KEY`: API key for `greynoise_ip_context`.
- `SENTINEL_API_KEY`: API key for `sentinel_ip_lookup`. A `sk_live_` secret key,
  sent as a bearer token.
- `CENSYS_API_KEY`: Personal access token for `censys_host_lookup`, sent as a
  bearer token against the Censys Platform API. This is the newer single-token
  scheme, not the legacy Search API's separate ID and secret.
- `VIRUSTOTAL_API_KEY`: API key for VirusTotal IP, domain, URL, and file reports.
- `SECURITYTRAILS_API_KEY`: API key for `securitytrails_domain_lookup`.
- `SHODAN_API_KEY`: API key for `shodan_host_lookup`.
- `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`: credentials for
  `threatsyft-update maxmind`, sent as HTTP basic auth. These are download
  credentials only; `maxmind_ip_lookup` reads the local database and needs no
  key at lookup time.
- `ALIENVAULT_API_KEY`: API key for `alienvault_indicator_lookup`.
- `GOOGLE_SAFEBROWSING_API_KEY`: API key for `google_safebrowsing_check_url`.
- `URLSCAN_API_KEY`: optional API key for `urlscan_search`, sent as the
  `API-Key` header. Search works without one at a lower quota, so this is the
  only provider key whose absence degrades a source rather than disabling it.
- `HYBRID_ANALYSIS_API_KEY`: API key for `hybrid_analysis_hash_lookup`, sent as
  the `api-key` header. Falcon Sandbox also requires a fixed
  `User-Agent: Falcon Sandbox` header, which the provider always sends.
- `NVD_API_KEY`: optional API key for the NVD CVE API.

Copy `.env.example` to `.env` for local API key setup. Do not commit `.env`.

`requirements.lock` records the exact versions the test suite passes against, for a reproducible rebuild:

```bash
.venv/bin/python -m pip install -r requirements.lock
```

`pyproject.toml` declares the supported ranges; the lock records one resolved point inside them.

The optional settings in `.env.example` are commented out on purpose. Each line shows its built-in default, so that section is documentation rather than configuration. Leave them commented unless you are changing one — an assignment with an empty value (`THREATSYFT_CISA_KEV_URL=`) is not the same as leaving a setting unset, it overrides the default with an empty string.

ThreatSyft loads `.env` from the working directory if there is one, then from `~/.threatsyft/.env`. The home location is the reliable one for MCP hosts, which start the server from their own working directory.

## Host Compatibility

ThreatSyft works with MCP hosts that can launch local stdio servers. The server code is host-generic; the only host-specific part is the configuration file format.

Install the project in a virtual environment:

```bash
python -m pip install -e .
```

Then configure your MCP host to launch the console scripts.

**Prefer the bare script name** (`threatsyft-enrichment-mcp`). It is the widest-supported form and survives moving or rebuilding the virtual environment.

**Fall back to the absolute path** (`/absolute/path/to/.venv/bin/threatsyft-enrichment-mcp`, or `...\.venv\Scripts\threatsyft-enrichment-mcp.exe` on Windows) when the host does not inherit your shell `PATH`. Several GUI hosts do not. The example configs below use the absolute form because it works everywhere; shorten it if your host resolves `PATH`.

ThreatSyft does not depend on the host's working directory: it loads `.env` from `~/.threatsyft/.env` as well as the working directory, so neither launch form needs a `cwd`.

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
- `Use ThreatSyft enrich on d41d8cd98f00b204e9800998ecf8427e.`
- `Use ThreatSyft lookup on T1059 and summarize what each source returned.`
- `Use ThreatSyft lookup on CVE-2024-3400 and tell me whether it is in KEV.`
- `Use ThreatSyft search for MOVEit and show me the matches per source.`
- `Use ThreatSyft lookup on APT29 and list the techniques it is recorded as using.`
- `Use ThreatSyft lookup on Certutil.exe and summarize defensive detection ideas.`
- `Use ThreatSyft extract_iocs on this incident note and list the indicators it found.`

`enrich` always calls every source that supports the indicator's type; there is no way to ask a single vendor, by design. Prefer `lookup` for one reference and `search` to find candidates across catalogs; `search(query, source=...)` narrows to one catalog when you want just that. Use `extract_iocs` to pull indicators out of text you already have, then enrich those values.

## Troubleshooting

- `missing_api_key`: the expected variable is absent. Check `.env`, or call `enrichment_status` for a local-only key-presence check that does not print secrets. A missing key is reported per source and the call still succeeds, so other sources still return data.
- `authentication_error`: the key exists but the provider rejected it.
- `rate_limited`: reported against the one source that rate-limited; every other source in the same call still returns, so the result is usable. Wait before retrying. A CVE `lookup` calls the live NVD API — set `NVD_API_KEY` in `.env` for a higher limit, or retry later.
- Slow RDAP or WHOIS: keep `THREATSYFT_TIMEOUT_SECONDS` at `15`, or temporarily raise it in `.env`.
- `not_found` with a missing snapshot path from an ATT&CK, KEV, or LOLBAS tool: run the matching `threatsyft-update <source>` (or `all`) once, then retry. Use `knowledge_status` for a local-only readiness check.
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

- `ARCHITECTURE.md` for MCP server boundaries, the response contract, and the reasoning behind both.
- `AGENTS.md` for standing instructions to future coding agents.
- `docs/testing.md` for the end-to-end checklist: setup states, agent prompts, and failure injection the hermetic suite cannot cover.
