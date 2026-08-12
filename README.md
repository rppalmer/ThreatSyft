# ThreatSyft

ThreatSyft gives an AI client — VS Code, Cursor, LM Studio — a set of security lookup tools over MCP: enrich an indicator, look up an ATT&CK or CVE reference, pull indicators out of text. MCP is the only interface; one console command downloads the local data.

It looks things up, it doesn't load pages. A URL passed to `enrich` is sent to reputation services as text, not visited. `extract_iocs` reads text you paste in. Fetching and summarising articles is the separate net-razor project.

## What It Does

Six tools across two servers.

**Enrichment server** — live provider calls for one indicator:

| Tool | Purpose |
| --- | --- |
| `enrich(indicator)` | Fan out to every source supporting an IP, domain, URL, or file hash |
| `enrichment_status()` | Which provider keys are configured, without calling anyone |

**Knowledge server** — local catalogs plus a live NVD call:

| Tool | Purpose |
| --- | --- |
| `lookup(reference)` | Resolve a CVE, ATT&CK ID, or bare name across every catalog covering it |
| `search(query, source, limit)` | Keyword search across ATT&CK, KEV, and LOLBAS, grouped by source |
| `extract_iocs(text)` | Pull typed indicators out of text you already have |
| `knowledge_status()` | Snapshot availability and age |

### Which sources back `enrich`

| Indicator | Sources |
| --- | --- |
| IP | AbuseIPDB, GreyNoise, Sentinel, VirusTotal, Shodan, Censys, MaxMind, mnemonic passive DNS, AlienVault OTX, RDAP, WHOIS |
| Domain | DNS, RDAP, WHOIS, VirusTotal, SecurityTrails, AlienVault OTX |
| URL | Google Safe Browsing, VirusTotal, urlscan.io, AlienVault OTX |
| Hash | VirusTotal, Hybrid Analysis, AlienVault OTX |

Every source for that indicator type is called; there's no option to query just one. DNS, RDAP, WHOIS, MaxMind and mnemonic need no key.

mnemonic answers what else has been hosted at an address and when — names seen resolving to it, with first and last observed dates. Its results are public passive DNS, capped at 1000 matches, so a count sitting at the cap is a floor rather than a total.

urlscan.io and Hybrid Analysis are read-only here: urlscan searches existing scans rather than submitting a new one, and Hybrid Analysis reads existing sandbox reports rather than detonating anything.

### Response shape

Every tool returns the same envelope:

```json
{ "ok": true, "tool": "enrich", "query": {}, "data": {}, "error": null }
```

Errors use the same shape with `data: null` and an `error` object carrying `code`, `message`, and `details`.

`ok: false` means the input needs changing — bad indicator, or a reference belonging to another tool. If every source fails the call is still `ok: true`, with each failure listed.

See `ARCHITECTURE.md` for the full contract.

## Install

```bash
python -m pip install -e .
```

Copy `.env.example` to `.env` and fill in the keys you have. Do not commit `.env`. ThreatSyft reads `.env` from the working directory, then `~/.threatsyft/.env` — the home location is the reliable one for MCP hosts, which start servers from their own working directory.

Then download the local data:

```bash
.venv/bin/threatsyft-update all
```

### API keys

Every key is optional. A missing key disables that one source; the rest of the call still returns. Run `enrichment_status()` to see what's configured.

| Variable | Used by |
| --- | --- |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `GREYNOISE_API_KEY` | GreyNoise |
| `SENTINEL_API_KEY` | Sentinel — a `sk_live_` secret key |
| `CENSYS_API_KEY` | Censys Platform personal access token, not the legacy ID/secret pair |
| `VIRUSTOTAL_API_KEY` | VirusTotal, all four indicator types |
| `SECURITYTRAILS_API_KEY` | SecurityTrails |
| `SHODAN_API_KEY` | Shodan |
| `ALIENVAULT_API_KEY` | AlienVault OTX |
| `GOOGLE_SAFEBROWSING_API_KEY` | Google Safe Browsing |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis |
| `URLSCAN_API_KEY` | urlscan.io — **optional**; search works without one at a lower quota |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | `threatsyft-update maxmind` only; lookups need no key |
| `NVD_API_KEY` | Optional; raises the NVD rate limit for CVE lookups |

### Optional settings

Paths and source URLs can be overridden — see `.env.example`, where each line is commented out and shows its built-in default. Leave them commented unless you are changing one: an empty assignment (`THREATSYFT_CISA_KEV_URL=`) overrides the default with an empty string rather than leaving it unset.

`THREATSYFT_TIMEOUT_SECONDS` (default `15`) is the one worth knowing about; raise it if RDAP or WHOIS is slow for you.

## Connecting an MCP Host

ThreatSyft works with any host that can launch local stdio servers. Only the config file format differs between hosts.

**Prefer the bare script name** — `threatsyft-enrichment-mcp` — which survives rebuilding the virtual environment. **Fall back to an absolute path** (`/path/to/.venv/bin/threatsyft-enrichment-mcp`, or `...\.venv\Scripts\threatsyft-enrichment-mcp.exe` on Windows) when the host does not inherit your shell `PATH`; several GUI hosts do not. Neither form needs a `cwd`.

VS Code uses `.vscode/mcp.json` with a `servers` object:

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

LM Studio and Cursor use the same shape under `mcpServers` instead of `servers`, with no `type` field. Copy-pasteable examples for all three live in `docs/mcp/`.

## Keeping Snapshots Current

Four data sets live on disk: MITRE ATT&CK, the CISA KEV catalog, LOLBAS, and the MaxMind GeoLite2 databases. Nothing refreshes them automatically — you run a command when something tells you to.

### The tools tell you when

When a snapshot goes too long without being checked against upstream, `lookup`, `search`, and `enrich` put a line in a top-level `warnings` list naming the source and the command that fixes it:

```
The kev snapshot has not been checked against upstream for 21 days
(stale after 14). Run `threatsyft-update kev` to refresh it.
```

The list is empty when everything is current.

### Refreshing

```bash
.venv/bin/threatsyft-update all
```

Or one source at a time: `attack`, `kev`, `lolbas`, `maxmind`.

Re-running is cheap: each source is asked whether anything changed before anything downloads, so an unchanged source costs one round trip and rewrites no files. A full `all` run with everything current takes under a second. Exit code `0` on success, `1` on failure, with a JSON result either way.

### When each source goes stale

| Source | Warns after | Why |
| --- | --- | --- |
| KEV | 14 days | CISA adds entries most weeks |
| GeoLite2 | 30 days | MaxMind rebuilds twice a week |
| ATT&CK | 180 days | A few releases a year |
| LOLBAS | 180 days | Slow-moving community catalog |

These count time since the last check, not the age of the data. If upstream hasn't published in months that's fine and nothing warns; the warning means nothing has checked recently.

Each snapshot-backed source also carries a `freshness` block with both: `as_of` and `age_days` for when upstream published, `checked_at` and `days_since_checked` for when the updater last got an answer.

## Tool Reference

### `enrich(indicator)`

Classifies one IP, domain, URL, or MD5/SHA1/SHA256 hash and collects context from every source supporting that type.

It returns no verdict and no score. Each provider's fields come back under that provider's own names — `last_analysis_stats`, `abuse_confidence_score`, `classification` — unchanged.

Returns `indicator`, `indicator_type`, a `source_summary` of `{ok, failed}` counts, a `sources` map where every entry has the same shape whether it succeeded or not, and `warnings`. Source order is fixed.

Passing a CVE or ATT&CK ID returns `ok: false` naming `lookup` instead.

### `lookup(reference)`

Resolves one reference across every local source covering it. Accepts:

- a CVE ID such as `CVE-2024-3400` — asks NVD (live) and the local KEV catalog
- an ATT&CK technique (`T1059`, `T1059.001`), tactic (`TA0002`), mitigation (`M1038`), group (`G0016`), or software (`S0002`) ID
- a bare name such as `Certutil.exe`, `execution`, `APT29`, or `Cozy Bear`

A bare name could be a LOLBAS binary, a tactic, or a threat actor alias, so `lookup` checks all three and the `sources` map shows which answered.

Group records list that group's techniques and the malware and tooling it uses; software records resolve the reverse. Same response shape as `enrich`.

Passing an IP, URL, or hash returns `ok: false` naming `enrich` instead.

### `search(query, source="all", limit=10)`

Keyword search across ATT&CK techniques, ATT&CK threat actors, KEV, and LOLBAS. Results stay grouped by source rather than merged into one ranked list.

`limit` applies **per source**, so `source="all"` returns up to `limit` rows from each. Each source reports `match_count` alongside `returned`, so you can tell 10-of-11 from 10-of-400.

Narrow with `source=` set to `attack_technique`, `attack_actor`, `kev`, or `lolbas` — the same names `lookup` uses in its `sources` map.

### `extract_iocs(text)`

Extracts typed IOC candidates from text. No network access. Handles defanged forms such as `hxxp://example[.]com`.

`iocs` holds values only, so you can feed them straight to `enrich`. The surrounding source text sits separately under `untrusted_context`, keyed by IOC value; drop that key and you still have every indicator.

`ioc_counts` is how many distinct indicators the text contains, before the per-type cap. `returned_counts` is how many came back. Types where they differ are listed in `truncated`.

### `enrichment_status()` and `knowledge_status()`

Readiness checks. Both are local, call no providers, and print no secret values. `enrichment_status` reports which keys are present and which indicator types each provider is called for. `knowledge_status` reports snapshot paths, availability, counts, ages, and the setup command for anything missing.

## Example Agent Prompts

- `Use ThreatSyft enrichment_status and tell me which providers are configured.`
- `Use ThreatSyft enrich on 8.8.8.8. Tell me which sources returned data and which failed.`
- `Use ThreatSyft enrich on https://example.com/ and explain any disagreement between sources.`
- `Use ThreatSyft lookup on CVE-2024-3400 and tell me whether it is in KEV.`
- `Use ThreatSyft lookup on APT29 and list the techniques it is recorded as using.`
- `Use ThreatSyft search for MOVEit and show me the matches per source.`
- `Use ThreatSyft extract_iocs on this incident note, then enrich the IPs it found.`

Benign indicators for manual checks: IP `8.8.8.8`, domain `example.com`, URL `https://example.com/`, MD5 `d41d8cd98f00b204e9800998ecf8427e`.

## Development

```bash
.venv/bin/python -m pip install -r requirements-dev.txt   # dependencies
.venv/bin/python -m pytest                                # tests
.venv/bin/ruff check .                                    # lint
.venv/bin/ruff format --check .                           # formatting
```

`requirements.lock` pins the exact versions the suite passes against; `pyproject.toml` declares the supported ranges.

```bash
.venv/bin/python -m pip install -r requirements.lock
```

The repository-local `.vscode/mcp.json` runs the servers through `.venv/bin/python -m ...` with `PYTHONPATH=src`, and VS Code tasks cover dependencies, lint, format, tests, and snapshot updates via `Tasks: Run Task`.

## Troubleshooting

- **`missing_api_key`** — the variable is absent. Check `.env`, or call `enrichment_status`. The call still succeeds and other sources still return.
- **`authentication_error`** — the key exists but the provider rejected it.
- **`rate_limited`** — reported against the one source that hit a limit; everything else in the call still returns. For CVE lookups, set `NVD_API_KEY` for a higher limit.
- **`not_found` naming a missing snapshot** — run the `threatsyft-update <source>` command in the error's `setup_command`, then retry.
- **Slow RDAP or WHOIS** — raise `THREATSYFT_TIMEOUT_SECONDS` in `.env`.
- **Tools not appearing in the host** — restart the MCP servers, and confirm the configured command path runs from a terminal.

## Further Reading

- `ARCHITECTURE.md` — server boundaries, the response contract, and the reasoning behind both
- `AGENTS.md` — standing instructions for coding agents
- `docs/testing.md` — end-to-end checklist: setup states, agent prompts, failure injection
