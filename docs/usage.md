# Investigatinator Usage Guide

This guide shows the fastest ways to test Investigatinator from the terminal and from an MCP-capable AI client.

## Terminal CLI

Run commands from the repository root:

```bash
cd path/to/Investigatinator-v2
```

Use direct aggregate commands based on the indicator type:

```bash
.venv/bin/python main.py --compact ip 8.8.8.8
.venv/bin/python main.py --compact domain example.com
.venv/bin/python main.py --compact url https://example.com/
.venv/bin/python main.py --compact file d41d8cd98f00b204e9800998ecf8427e
```

Leave `--compact` off when you want full provider details:

```bash
.venv/bin/python main.py domain example.com
```

Show help:

```bash
.venv/bin/python main.py --help
.venv/bin/python main.py domain --help
```

Run local-only checks for configuration and available tools:

```bash
.venv/bin/python main.py doctor
.venv/bin/python main.py --compact doctor
.venv/bin/python main.py tools
.venv/bin/python main.py --compact tools
.venv/bin/python main.py knowledge-status
.venv/bin/python main.py --compact knowledge-status
```

Run live smoke checks against safe sample indicators. This uses provider calls and may consume quota:

```bash
.venv/bin/python main.py --compact smoke
```

Successful lookups exit with code `0`. Invalid input or failed lookups exit with code `1` while still printing a structured JSON error.

## Local MITRE ATT&CK Knowledge

Download or refresh the local Enterprise ATT&CK snapshot:

```bash
.venv/bin/python main.py knowledge-update attack
```

Knowledge MCP lookups are local-only at runtime. They read `~/.investigatinator/knowledge/attack/enterprise-attack.json` by default and do not call MITRE during normal tool use.

Download or refresh the local D3FEND snapshot:

```bash
.venv/bin/python main.py knowledge-update d3fend
```

D3FEND MCP lookups are local-only at runtime. They read `~/.investigatinator/knowledge/d3fend/d3fend.json` by default and map ATT&CK behavior to defensive technique context.

Download or refresh the local CISA KEV snapshot:

```bash
.venv/bin/python main.py knowledge-update kev
```

CISA KEV MCP lookups are local-only at runtime. They read `~/.investigatinator/knowledge/cisa/known_exploited_vulnerabilities.json` by default and do not call CISA during normal tool use.

Download or refresh the local LOLBAS snapshot:

```bash
.venv/bin/python main.py knowledge-update lolbas
```

LOLBAS MCP lookups are local-only at runtime. They read `~/.investigatinator/knowledge/lolbas/lolbas.json` by default and return defensive context while omitting raw command examples.

Check all local knowledge snapshot status without calling external providers:

```bash
.venv/bin/python main.py --compact knowledge-status
```

Refresh all local knowledge snapshots in sequence:

```bash
.venv/bin/python main.py knowledge-update all
```

Knowledge update commands use live network access to download snapshots. They do not run automatically during MCP lookups.

## Safe Test Indicators

Useful benign-ish smoke test values:

- IP: `8.8.8.8`
- Domain: `example.com`
- URL: `https://example.com/`
- MD5: `d41d8cd98f00b204e9800998ecf8427e`

Use your own suspicious indicators when you want real investigative value, but remember that provider verdicts can disagree. Treat aggregate results as evidence bundles for the agent, not final truth.

## VS Code Tasks

Open the Command Palette and run:

- `Tasks: Run Task`
- `Investigatinator: CLI domain example.com`
- `Investigatinator: CLI help`
- `Investigatinator: CLI doctor`
- `Investigatinator: CLI tools`
- `Investigatinator: CLI smoke safe samples`
- `Investigatinator: Knowledge status`
- `Investigatinator: Knowledge update all`

These tasks are convenience wrappers around `main.py`.

## MCP Use

Investigatinator's MCP servers are local stdio processes. Install the package in
your virtual environment:

```bash
python -m pip install -e .
```

Then point any local stdio-capable MCP host at one or more of these console
scripts:

```bash
investigatinator-enrichment-mcp
investigatinator-knowledge-mcp
investigatinator-research-mcp
```

If your MCP host does not inherit your shell `PATH`, use absolute paths to the
scripts in your virtual environment:

```text
/absolute/path/to/.venv/bin/investigatinator-enrichment-mcp
/absolute/path/to/.venv/bin/investigatinator-knowledge-mcp
/absolute/path/to/.venv/bin/investigatinator-research-mcp
```

Copy-pasteable config examples are available here:

- `docs/mcp/lm-studio.example.json`
- `docs/mcp/cursor.example.json`
- `docs/mcp/vscode.example.json`

LM Studio and Cursor use Cursor-style `mcp.json` files with a top-level
`mcpServers` object. VS Code uses `.vscode/mcp.json` with a top-level `servers`
object. The repository-local `.vscode/mcp.json` is only a development
convenience around the same server modules.

After your host discovers the servers, ask the agent to use tools like:

```text
Use Investigatinator enrichment_status and tell me which enrichment providers are configured. Do not print secret values.
```

```text
Use Investigatinator domain_reputation on example.com and summarize the key signals.
```

```text
Use Investigatinator ip_reputation on 8.8.8.8. Tell me which providers returned results and which failed.
```

```text
Use Investigatinator research_feed_status and tell me which RSS feeds are configured.
```

```text
Use Investigatinator url_reputation on https://example.com/ and explain any provider disagreement.
```

```text
Use Investigatinator virustotal_file_report on d41d8cd98f00b204e9800998ecf8427e.
```

```text
Use Investigatinator attack_technique_lookup on T1059 and explain the defensive context.
```

```text
Use Investigatinator attack_search for PowerShell with a limit of 5.
```

```text
Use Investigatinator attack_tactic_lookup on Initial Access and list the related techniques.
```

```text
Use Investigatinator attack_defense_mapping on T1059 and explain the defensive techniques.
```

```text
Use Investigatinator d3fend_lookup on File Analysis.
```

```text
Use Investigatinator technique_brief on T1059 and summarize the key defensive context.
```

```text
Use Investigatinator cve_lookup on CVE-2024-3400 and explain the NVD severity and CISA fields.
```

```text
Use Investigatinator vulnerability_brief on CVE-2024-3400 and summarize the NVD and KEV evidence.
```

```text
Use Investigatinator kev_lookup on CVE-2024-3400 and tell me if it appears in CISA KEV.
```

```text
Use Investigatinator kev_search for MOVEit with a limit of 5.
```

```text
Use Investigatinator lolbas_lookup on Certutil.exe and summarize defensive detection ideas.
```

```text
Use Investigatinator lolbas_search for T1105 with a limit of 5.
```

```text
Use Investigatinator knowledge_status and tell me which local snapshots are ready.
```

```text
Use Investigatinator research_feed_search for ransomware with a limit of 5.
```

```text
Use Investigatinator research_article_summary on https://example.com/report and summarize the key public-report context.
```

```text
Use Investigatinator research_article_iocs on https://example.com/report and list the extracted indicators.
```

```text
Use Investigatinator research_brief on https://example.com/report. Summarize the returned fact pack and do not call the research tools again for that same URL unless I ask you to refresh it.
```

Use provider-specific tools when you need raw provider detail or want to isolate one data source.
Use ATT&CK knowledge tools when you need stable defensive technique context rather than provider reputation data.
Use research tools when you need recent public reporting context or IOC extraction from a known article URL. Use `research_brief` when you want one article fact pack with suggested follow-up pivots, without automatic enrichment.

## Troubleshooting

If a tool returns `missing_api_key`, check `.env` and confirm the expected variable is present.

For a quick local-only key-presence check that does not print secrets:

```bash
.venv/bin/python main.py --compact doctor
```

If a tool returns `authentication_error`, the key exists but the provider rejected it.

If a tool returns `rate_limited`, wait or use a different provider-specific tool.

`cve_lookup` uses the live NVD CVE API. If it returns `rate_limited`, configure `NVD_API_KEY` in `.env` or retry later.

If RDAP or WHOIS seems slow, keep `INVESTIGATINATOR_TIMEOUT_SECONDS` at `15` or temporarily increase it in `.env`.

If ATT&CK tools return `not_found` with a missing snapshot path, run:

```bash
investigatinator knowledge-update attack
```

If D3FEND tools return `not_found` with a missing snapshot path, run:

```bash
investigatinator knowledge-update d3fend
```

If KEV tools return `not_found` with a missing snapshot path, run:

```bash
investigatinator knowledge-update kev
```

If LOLBAS tools return `not_found` with a missing snapshot path, run:

```bash
investigatinator knowledge-update lolbas
```

Use `knowledge_status` from the MCP server or `main.py knowledge-status` from the CLI when you want a local-only readiness check for ATT&CK, D3FEND, KEV, and LOLBAS snapshots. It includes local file modified timestamps for each snapshot and source update timestamps when the source data exposes them. It does not report RSS feeds or research source configuration; use `research_feed_status` for that.

If VS Code does not show the MCP tools, restart the MCP servers from the Command
Palette and confirm `.vscode/mcp.json` points to
`${workspaceFolder}/.venv/bin/python`. For LM Studio or Cursor, confirm the
configured command path exists and can be run from a terminal.
