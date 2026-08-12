# ThreatSyft

ThreatSyft exposes focused security tools through local MCP servers, so an AI client such as VS Code can request structured security context without getting general-purpose access to the machine. MCP is the only interface; one console command exists to download data snapshots.

It does **not** discover, fetch, or summarise threat reports. That belongs to the separate net-razor project. ThreatSyft never fetches a URL you hand it — `extract_iocs` works on text you already have.

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
| IP | AbuseIPDB, GreyNoise, Sentinel, VirusTotal, Shodan, Censys, MaxMind, AlienVault OTX, RDAP, WHOIS |
| Domain | DNS, RDAP, WHOIS, VirusTotal, SecurityTrails, AlienVault OTX |
| URL | Google Safe Browsing, VirusTotal, urlscan.io, AlienVault OTX |
| Hash | VirusTotal, Hybrid Analysis, AlienVault OTX |

Everything supporting the indicator's type is called — there is no way to ask a single vendor, by design. Sources that need no key at all: DNS, RDAP, WHOIS, and MaxMind (which reads a local database).

Two providers read only, never act: **urlscan.io** searches existing scans and never submits one, and **Hybrid Analysis** reads existing sandbox reports and never detonates a sample. Submitting would both act against the target and publish the fact that you are investigating it.

### Response shape

Every tool returns the same envelope:

```json
{ "ok": true, "tool": "enrich", "query": {}, "data": {}, "error": null }
```

Errors use the same shape with `data: null` and an `error` object carrying `code`, `message`, and `details`.

`ok: false` means *the caller must change something* — bad input, or a reference belonging to another tool. Every source failing is still `ok: true` with the failures attributed, because retrying will not fix an absence of data.

`ARCHITECTURE.md` explains the contract and the reasoning behind it.

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

Every key is optional. A missing key disables that one source and is reported per source; the rest of the call still returns. Run `enrichment_status()` to see what is configured without printing secrets.

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

On a current install that list is empty, so anything appearing there needs doing.

### Refreshing

```bash
.venv/bin/threatsyft-update all
```

Or one source at a time: `attack`, `kev`, `lolbas`, `maxmind`.

Re-running is cheap. Each source is asked whether anything changed before anything downloads, so an unchanged source costs one round trip and rewrites no files — a full `all` run with everything current takes under a second. Exit code is `0` on success, `1` on failure, and a structured JSON result prints either way.

### When each source goes stale

| Source | Warns after | Why |
| --- | --- | --- |
| KEV | 14 days | CISA adds entries most weeks |
| GeoLite2 | 30 days | MaxMind rebuilds twice a week |
| ATT&CK | 180 days | A few releases a year |
| LOLBAS | 180 days | Slow-moving community catalog |

The clock is on **checking**, not on the data. A source upstream has not touched in months will not warn as long as you have asked recently; what warns is nobody asking.

Every snapshot-backed source also carries a `freshness` block reporting both: `as_of` and `age_days` for when upstream published the data, `checked_at` and `days_since_checked` for when the updater last got an answer.

## Tool Reference

### `enrich(indicator)`

Classifies one IP, domain, URL, or MD5/SHA1/SHA256 hash and collects context from every source supporting that type.

This is collection, not judgement. It returns **no** verdict and no confidence score, per source or overall. Each provider's own fields come back under that provider's own names — `last_analysis_stats`, `abuse_confidence_score`, `classification` — and nothing reduces them. Interpretation is the calling agent's job.

Returns `indicator`, `indicator_type`, a `source_summary` of `{ok, failed}` counts, a `sources` map keyed by source name where every entry has the same shape whether it succeeded or not, and `warnings`. Source order is fixed regardless of which source responds first.

Passing a CVE or ATT&CK ID returns `ok: false` naming `lookup` instead.

### `lookup(reference)`

Resolves one reference across every local source covering it. Accepts:

- a CVE ID such as `CVE-2024-3400` — asks NVD (live) and the local KEV catalog
- an ATT&CK technique (`T1059`, `T1059.001`), tactic (`TA0002`), mitigation (`M1038`), group (`G0016`), or software (`S0002`) ID
- a bare name such as `Certutil.exe`, `execution`, `APT29`, or `Cozy Bear`

A bare name is ambiguous — it could be a LOLBAS binary, a tactic, or a threat actor alias — so `lookup` asks all three rather than guessing. They are local and fast, and the `sources` map shows which answered.

Group records list the techniques and the malware and tooling that group is recorded using; software records resolve the reverse. Returns the same envelope shape as `enrich`.

Passing an IP, URL, or hash returns `ok: false` naming `enrich` instead.

### `search(query, source="all", limit=10)`

Keyword search across ATT&CK techniques, ATT&CK threat actors, KEV, and LOLBAS, grouped by source and never merged into one ranked list — the catalogs share almost no fields and their scores are on unrelated scales, so a combined ranking would invent precision that does not exist.

`limit` applies **per source**, so `source="all"` does not quietly return three times the rows you asked for. Each source reports `match_count` alongside `returned`, so you can tell 10-of-11 from 10-of-400.

Narrow with `source=` set to `attack_technique`, `attack_actor`, `kev`, or `lolbas` — the same names `lookup` uses in its `sources` map.

### `extract_iocs(text)`

Extracts typed IOC candidates from text. No network access. Handles defanged forms such as `hxxp://example[.]com`.

`iocs` carries values only, so a caller can feed them straight to `enrich`. Surrounding source text stays under `untrusted_context`, keyed by IOC value, never merged into a server-authored field — a caller can drop that key entirely without losing an indicator.

`ioc_counts` is how many distinct indicators the text contains, counted before the per-type cap; `returned_counts` is how many came back. They differ exactly for the types listed in `truncated`, so a long report that overflows the cap says so rather than silently losing indicators.

### `enrichment_status()` and `knowledge_status()`

Local-only readiness checks that call no providers and print no secret values. `enrichment_status` reports per-provider key presence and which indicator types each is called for, derived from the dispatch table so it cannot claim coverage that no longer exists. `knowledge_status` reports snapshot paths, availability, counts, ages, and the setup command for anything missing.

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
