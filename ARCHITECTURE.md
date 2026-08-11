# ThreatSyft Architecture

ThreatSyft exposes focused, read-only security capabilities to an AI client through MCP, keeping the investigation logic in ordinary Python modules. MCP is the only interface; the one console command downloads snapshots, which cannot live behind a tool call without breaking the servers' read-only posture.

The consuming agent is the reasoning layer. These tools collect; they do not judge.

## The two servers

```text
threatsyft-enrichment   holds every API key, spends money
threatsyft-knowledge    no keys, no metered calls
```

| Server | Tool | Purpose |
|---|---|---|
| enrichment | `enrich(indicator)` | Classify an IP, domain, URL or file hash and fan out concurrently to every source supporting that type. |
| enrichment | `enrichment_status()` | Which API keys are present. No secret values, no network. |
| knowledge | `lookup(reference)` | Classify a CVE, ATT&CK technique, tactic, mitigation, threat actor, software or LOLBAS name and collect every source covering it. |
| knowledge | `search(query, source, limit)` | Keyword search across ATT&CK techniques, threat actors, KEV and LOLBAS, grouped by source. |
| knowledge | `extract_iocs(text)` | Typed IOC candidates from text the caller already has. No network. |
| knowledge | `knowledge_status()` | Snapshot readiness. |

Six tools. The per-source functions behind them all still exist as ordinary Python and are individually tested; they are simply not exposed as separate tools, because a smaller surface makes tool selection more reliable.

The MCP transports in `src/threatsyft/mcp/` stay thin: register tools, accept explicit inputs, delegate. Core logic lives in `src/threatsyft/enrichment/` and `src/threatsyft/knowledge/`, usable outside MCP including from tests. `core.py` and `fanout.py` sit at the top level because both packages depend on them equally.

## Where the boundary is

Public reporting discovery, article fetching and summarisation are out of scope and live in the separate net-razor project, which already carries the trust class for retrieving content it did not author. ThreatSyft never fetches a URL it is handed.

The boundary is strict in both directions: ThreatSyft never calls net-razor and net-razor never calls ThreatSyft. MCP servers expose capabilities and the *client* composes them. Server-to-server calls would make each a client of the other, with its own config, credentials and failure handling for the peer. Calling third-party HTTP APIs is not a boundary violation; only MCP-to-MCP is.

This is also the prompt-injection control. The intended flow keeps article text out of any credential-holding step:

```text
fetch node    → net-razor.fetch(url)                 → state["article_text"]
extract node  → threatsyft.extract_iocs(state[...])  → state["iocs"]   (typed values)
enrich node   → threatsyft.enrich(ioc) per ioc
```

Separating the node that reads untrusted content from the node holding credentials, and passing typed values between them, falls out of the architecture rather than being a control someone has to remember to apply. It only works *because* the boundary is strict.

## The response contract

Every tool returns the same envelope:

```json
{"ok": true, "tool": "enrich", "query": {}, "data": {}, "error": null}
```

Errors use the same shape with `ok: false`, `data: null`, and `error` carrying `code`, `message` and optional `details`.

### One `sources` map across `enrich`, `lookup` and `search`

All three collection tools return results the same way, so a caller written against one iterates the others unchanged:

```json
{"data": {
  "indicator_type": "ip",
  "source_summary": {"ok": 3, "failed": 1},
  "sources": {
    "abuseipdb":  {"ok": true,  "data": {}},
    "virustotal": {"ok": false, "code": "rate_limited", "message": "..."}
  }}}
```

Every entry has the same shape whether it succeeded or not, so a consumer iterates one structure instead of correlating a results map against an errors list. `source_summary` lets a node answer "did anything work?" without iterating. The type is echoed back so an agent that guessed wrong can self-correct. Source ordering is fixed and independent of which source answers first.

One vocabulary too, not just one shape. The ATT&CK technique catalog is `attack_technique` in a `lookup` response, in a `search` response and in `search`'s `source` argument; the same holds for `attack_actor`. A shared shape with two names for the same catalog would still make a caller translate.

ATT&CK software is `attack_software`, reachable by S-id. Malware and tooling are two STIX types sharing one S-numbering space, so they are one catalog here for the reason ATT&CK numbers them together: a caller asking what a group uses wants both. `software_type` preserves which one each entry is rather than flattening the distinction away. An actor record carries `software`/`software_count` in the same trimmed identity shape as `techniques`, and the edge reads from either end — a software lookup lists the actors recorded as using it.

A source that raises rather than returning an envelope becomes that source's `unexpected_error` entry. Letting it propagate would return no envelope at all and discard what every other source had already found, which is the opposite of what the shape promises.

### `ok: false` means the caller must change something

| Situation | Result |
|---|---|
| Input invalid or unclassifiable | `ok: false`, `invalid_input` |
| Right input, wrong tool | `ok: false`, `invalid_input`, with `details.suggested_tool` |
| Some sources failed | `ok: true`, failures attributed per source |
| **Every** source failed | `ok: true`, `source_summary.ok == 0` |

"I asked four sources and all four failed" is a successful execution with an informative result, not a tool error. For a retrying agent, `ok: false` should mean "you did something wrong", not "the world had no data", which retrying will not fix.

### No verdict, anywhere

Parallel fetch is fine; scoring is not. `enrich` calls many sources at once and reports what each returned, and deliberately produces no overall verdict or confidence score. Such a value silently changes meaning when one provider rate-limits — the same indicator scores differently because of a 429 rather than because of evidence — and the caller cannot see that happen.

The rule is per source as well as across them. A provider's own fields pass through under the provider's own names — VirusTotal's `last_analysis_stats`, AbuseIPDB's `abuse_confidence_score`, GreyNoise's `classification`, Safe Browsing's `matched` — and ThreatSyft adds no field of its own that reduces them. Every source once carried a project-computed `verdict` built from local thresholds; those are gone. They failed the same test the aggregate does: "one engine of 43 flagged this" became `malicious`, "the host has a CVE" became `suspicious`, and "no reports" became `benign`, each losing the evidence that made the claim weak. Every one of them was derivable by the caller from fields that are still there, which is where that judgement belongs.

### Responses stay small by default, and stay navigable

Large fields are trimmed to identity rather than hidden behind a verbosity flag. A technique returns its mitigations as `{id, name, url}`; the full write-up is `lookup("M1038")` away. A flag would make the model choose how much detail it wants before seeing any, so it would either always ask for everything or guess.

Trimming and omitting are different, and only one thing is omitted. Everything trimmed keeps its ID and is reachable by a follow-up `lookup`: mitigations, subtechniques, a tactic's technique list, an actor's technique list, KEV search rows. LOLBAS command examples are the exception — they are working invocations of the abuse, no tool returns them, and the entry says so in `command_examples_note` rather than leaving a caller to hunt for a call that does not exist. The defensive half of that catalog, `detections`, is returned in full.

### Snapshot age rides along

Every snapshot-backed source reports its age and whether that age is past a per-source threshold — 14 days for KEV, which CISA updates most weeks, 180 for ATT&CK and LOLBAS, which change a few times a year. This applies on the failure path especially: "this CVE is not in KEV" reads as "not known to be exploited", when on a stale catalog the honest claim is "not exploited as of whenever this last refreshed".

Age is reported, never enforced. Refusing to answer past a threshold would break the offline case the snapshots exist for.

## Boundary guidance

Keep server boundaries tied to the question each tool answers. Do not add more MCP servers unless a capability has meaningfully different behaviour or maintenance needs.

- Indicator facts and provider reputation belong in enrichment.
- Stable references and defensive knowledge belong in knowledge.
- Fresh public reporting and article processing belong in net-razor. General rule: put the capability where the trust class already exists.

Knowledge lookups read local snapshots. The NVD CVE API is the one live call, because a full CVE mirror is too large to keep locally. Snapshot downloads are the job of `threatsyft-update`.

## Safety posture

ThreatSyft is defensive by default.

In scope: enrichment, triage, technique mapping, detection- and mitigation-oriented explanation, IOC extraction from text, current vulnerability and KEV context.

Out of scope unless deliberately reconsidered: generic command execution, credential handling beyond local API key configuration, exploit generation, payload generation, EDR bypass instructions, offensive automation, active scanning or probing, submitting reports or changing third-party state.

Any future active capability requires a separate architecture review and explicit approval.
