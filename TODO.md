# ThreatSyft — Rework Plan

Working tracker for the architecture rework agreed 2026-08-08/09, following the design and
implementation review. Full finding detail lives in the review artifact; this file carries
the decisions, the contracts, and the work.

Review artifact: https://claude.ai/code/artifact/71b13526-c2eb-4f5e-a6c5-3403f8a40df8

---

## 0. Where things stand

Last updated 2026-08-09, after Phase 1b.

| Phase | State |
|---|---|
| Phase 0 (H1, H2, H5) | Done, committed |
| Phase 1a (move `iocs.py`, add its tests) | Done, committed |
| Phase 1b (delete research) | Done, committed |
| Phase 2 (collapse enrichment to `enrich()`) | Not started — next |
| Phases 3–4 | Not started. Codebase otherwise as reviewed. |

Suite: 271 passing. `ruff check` and `ruff format --check` clean. The count fell from 295
because 1b deleted ~520 lines of research tests; nothing regressed.

Also removed after 1b: the vestigial "not RSS feeds / news sources" disclaimers in
`knowledge/status.py`, the `knowledge_status` docstring and the README. They existed only
to steer a model away from the research server, so they pointed at nothing once it left.

Phases 0 and 1 landed as **one commit**, not the three the workflow intended. They had
accumulated in a single working tree before anything was committed, and `config.py` and
`pyproject.toml` each carried both Phase 0 and Phase 1b changes. Any Phase-0-only commit
would therefore have held a `config.py` stripped of the research helpers while
`research/feeds.py` still imported them — a commit that does not import. One green commit
beat three commits where the first two are broken. From Phase 2 on, commit per chunk and
this cannot recur.

Nothing here has been exercised against a live MCP host or a real provider; the suite is
hermetic by design. **H1 in particular cannot be proven by it** — its failure mode is the
host's working directory, which the unit tests do not reproduce. Worth one manual check
against a real host before trusting the `.env` fix.

**Goal.** Hand an agent an IOC or a reference and have it collect everything the configured
sources can say about it, in one call. Collection, not judgement — the agent is the
reasoning layer.

**Scale of the change.** ~4,240 lines removed, ~440 added, 38 tools → 6. Almost entirely
deletion: the provider modules, `run_providers`, `snapshot_cache`, the `core.py` envelope
and the input classifiers all survive untouched. What goes is the scaffolding on top.

---

## 1. Target architecture

### `threatsyft-enrichment` — holds all API keys, spends money

| Tool | Purpose |
|---|---|
| `enrich(indicator)` | Classify the indicator, fan out concurrently to every provider supporting that type. No verdict, no confidence. |
| `enrichment_status()` | Key presence. No secret values, no network. |

### `threatsyft-reference` — no keys, no metered calls

| Tool | Purpose |
|---|---|
| `lookup(reference)` | Classify CVE-id / ATT&CK T-id / LOLBAS name, fan out to applicable local sources. |
| `search(query, source="all", limit=10)` | Search ATT&CK / KEV / LOLBAS. |
| `extract_iocs(text)` | Typed IOC candidates from arbitrary text. No network. |
| `reference_status()` | Snapshot readiness and age. |

Naming: `threatsyft-local` was rejected because `cve_lookup` hits NVD live, so the server is
not offline. `reference` describes what it serves without promising something untrue.

### Out of scope — belongs to net-razor

RSS feed search, article fetching, article summarisation. net-razor already owns discovery
and already retrieves content it did not author, so it already carries that trust class.

---

## 2. Decisions

| Decision | Rationale |
|---|---|
| **MCP is the only consumer** | CLI retired except snapshot updates. |
| **Consumer is a LangGraph multi-node graph** | Single agent is a supported case; design for the graph, don't require it. |
| **D3FEND dropped** | Add back later if the mapping data proves necessary. Largest single deletion. |
| **No cost-tier parameter on `enrich()`** | Always call everything. Running out of credit degrades to less data, attributed per provider. |
| **No quota tracking at all** | See §6. |
| **Response size fixed by trimming defaults, not a verbosity knob** | A knob pushes a decision onto the model on every call. |
| **Strict server boundaries; the graph composes** | See below. |
| **No scalar verdict or confidence anywhere** | Untested heuristic in the trust path; contradicts the stated design intent. |

### On strict boundaries

ThreatSyft never calls net-razor and net-razor never calls ThreatSyft. MCP servers expose
capabilities and the *client* composes them — server-to-server calls would make each server
a client of the other, with its own config, credentials and failure handling for the peer.
Calling third-party HTTP APIs (VirusTotal, NVD) is not a boundary violation; only MCP-to-MCP
is.

Intended flow, with article text never entering an LLM context:

    fetch node    → net-razor.fetch(url)                 → state["article_text"]
    extract node  → threatsyft.extract_iocs(state[...])  → state["iocs"]   (typed)
    enrich node   → threatsyft.enrich(ioc) per ioc

This is also the prompt-injection fix. Separating the node that reads untrusted content from
the node holding credentials, and passing typed values between them, falls out of the
architecture instead of being a control someone has to remember to apply. It only works
*because* the boundary is strict — if ThreatSyft fetched the article itself, the separation
would have nowhere to live.

If net-razor currently returns only snippets, add a fetch tool **to net-razor**. General
rule: put the capability where the trust class already exists.

---

## 3. Response contracts

The one genuinely new design in this plan. Everything else is subtraction.

### 3.1 The envelope drops `ok`

`ok` and `error` encode the same fact twice — `ok: false` always carries an error and
`ok: true` never does. Two fields for one truth can disagree, which is the same defect as
the envelope-versus-`isError` split in H6, one level down. Decided 2026-08-09: remove `ok`
and let `error` be the signal, with `error` moved to first position so it is still the first
thing a model reads.

    {
      "error": null,
      "tool": "enrich",
      "query": {"indicator": "8.8.8.8"},
      "data": { ... }
    }

The check becomes `if result["error"]`. Matches JSON-RPC convention, which matters because
MCP is JSON-RPC underneath. Everything else about the envelope is unchanged.

Sequencing: do this **after** the Phase 1 deletions, so it touches the smallest possible
amount of code. It reaches every tool and every test either way.

Note that per-source entries inside `sources` (§3.2) keep their own `ok` boolean — there the
alternative would be a nullable error per source, and a flat boolean reads better in a map
a node iterates. The redundancy argument applies to the top-level envelope, where `error`
already carries the structure.

### 3.2 One `sources` map, identical across `enrich`, `lookup` and `search`

Today's aggregates split results into `provider_results` and `provider_errors`, forcing a
consumer to look in two places and correlate by name. Replace both with a single map keyed
by source, where every entry has the same shape whether it succeeded or not:

```json
{
  "ok": true,
  "tool": "enrich",
  "query": {"indicator": "8.8.8.8"},
  "data": {
    "indicator": "8.8.8.8",
    "indicator_type": "ip",
    "source_summary": {"ok": 3, "failed": 1},
    "sources": {
      "abuseipdb":  {"ok": true,  "data": {...}},
      "greynoise":  {"ok": true,  "data": {...}},
      "shodan":     {"ok": true,  "data": {...}},
      "virustotal": {"ok": false, "code": "rate_limited",
                     "message": "VirusTotal rate limit was reached."}
    }
  },
  "error": null
}
```

Why this shape:

- **One iteration pattern for all three tools.** A graph node written against `enrich`
  works against `lookup` and `search` unchanged.
- **`source_summary` lets a node branch without iterating.** Cheap "did anything work?"
  check.
- **`indicator_type` is echoed back** so an agent that guessed wrong can self-correct. This
  is the mitigation for losing per-type schema validation — one `indicator: str` argument
  cannot catch what `ip: str` vs `domain: str` used to.
- Source ordering stays fixed and independent of response arrival order, as
  `aggregate.run_providers` already guarantees.

### 3.3 `ok: false` means the caller must change something

Decided for consistency across every tool. Today the rule is arbitrary: aggregates return
`upstream_error` when *all* providers fail but `ok: true` when only some do, so the
threshold between success and failure is a count.

New rule — **`ok: false` if and only if the tool could not do its job**:

| Situation | Result |
|---|---|
| Input invalid or unclassifiable | `ok: false`, `invalid_input` |
| Right input, wrong tool | `ok: false`, `invalid_input`, with `details.suggested_tool` |
| Snapshot missing or unreadable | `ok: false`, `not_found`, with `details.setup_command` |
| Some sources failed | `ok: true`, failures attributed in `sources` |
| **Every** source failed | `ok: true`, all failures attributed, `source_summary.ok == 0` |
| No sources exist for this type | `ok: true`, empty `sources`, `source_summary.ok == 0` |

"I asked four sources and all four failed" is a *successful* execution with an informative
result, not a tool error. For a retrying graph node, `ok: false` should mean "you did
something wrong" — not "the world had no data", which retrying will not fix.

### 3.4 Wrong tool for the input

`enrich("CVE-2024-1234")` is a plausible agent mistake and should be self-correcting:

```json
{"ok": false, "tool": "enrich",
 "error": {"code": "invalid_input",
           "message": "CVE-2024-1234 is a vulnerability reference, not an enrichable indicator.",
           "details": {"detected_type": "cve", "suggested_tool": "lookup"}}}
```

`ok: false` because the caller made a mistake — but the error names the right tool, which
costs nothing and turns a dead end into a redirect. Applies symmetrically: `lookup` on an
IP should point at `enrich`.

### 3.5 `search` groups by source and never merge-ranks

ATT&CK techniques, KEV entries and LOLBAS binaries share almost no fields, and their three
scoring functions produce numbers on unrelated scales. Merging them into one ranked list
would invent a precision that does not exist.

```json
{"data": {
  "query": "powershell",
  "source_summary": {"ok": 3, "failed": 0},
  "sources": {
    "attack": {"ok": true, "match_count": 47, "returned": 10, "matches": [...]},
    "kev":    {"ok": true, "match_count":  3, "returned":  3, "matches": [...]},
    "lolbas": {"ok": true, "match_count": 12, "returned": 10, "matches": [...]}
  }}}
```

- `limit` applies **per source**, so `source="all"` does not silently return 3× the
  requested rows.
- `match_count` (total available) alongside `returned` closes M8 — today a model cannot
  tell 10-of-11 from 10-of-400.

### 3.6 `extract_iocs` keeps untrusted text structurally separate

Designed as a **typed hand-off between graph nodes**, not prose for a model to read:

```json
{"data": {
  "iocs": {
    "ips":     [{"value": "203.0.113.45", "type": "ipv4"}],
    "domains": [{"value": "evil.example.com"}],
    "urls":    [], "hashes": [], "cves": [{"value": "CVE-2026-11111"}]
  },
  "ioc_counts": {"ips": 1, "domains": 1, "urls": 0, "hashes": 0, "cves": 1},
  "untrusted_context": {
    "203.0.113.45": ["...surrounding source text..."]
  }
}}
```

- `iocs` carries **values only** — safe for a node to iterate and feed straight to `enrich`.
- Source text lives under `untrusted_context`, keyed by IOC, and is never merged into any
  server-authored field. A consumer can drop the whole key without losing the indicators.
- No `suggested_next_pivots`. The graph decides what to enrich; the old pivot list existed
  to steer an agent that could not see the structure.

### 3.7 Trim the default payload

`attack_technique_lookup("T1059")` is ~10,753 tokens. Measured breakdown — the review text
blaming `references` was wrong, it is 3%:

| field | tokens | share |
|---|---|---|
| `mitigations` | 5,885 | 55% |
| `subtechniques` | 3,494 | 33% |
| `description` | 455 | 4% |
| `references` | 318 | 3% |

Two fields are 87%. Fixes:

- `mitigations` — nine entries each carrying full prose `description` (`attack.py:333-338`).
  Return `mitigation_id` + `name` + `source_url`.
- `subtechniques` — thirteen full `_technique_summary` objects (`attack.py:390-394`), each
  re-embedding complete tactic objects, so tactic descriptions repeat thirteen times in one
  response. Return IDs and names.
- `_tactic_data` (`attack.py:412`) inlines the tactic `description` wherever a tactic
  appears. Keep it on the top-level technique only.
- `whois_lookup` returns the entire raw record — full WHOIS text (`whois.py:65`) and the
  complete RDAP object (`whois.py:120`). Drop `raw` or cap it hard.

Target: **~10,750 → ~1,400 tokens**, no new parameter.

### 3.8 Snapshot freshness on every reference response

Every `lookup` and `search` response carries `snapshot_as_of` and a `stale` boolean, on
success *and* failure. The sharp case today: `kev.py:67-74` returns `not_found` with only
`snapshot_path` — `_catalog_metadata` at `:286` has `date_released` right there but is only
called on the success path, so "this CVE is not in KEV" carries no indication whether the
catalog is a day or a year old.

Per-source thresholds; a single global one would be wrong. KEV changes weekly, ATT&CK a few
times a year:

| source | `stale_after_days` |
|---|---|
| kev | 14 |
| attack | 180 |
| lolbas | 180 |

Carry `as_of` rather than refuse past a threshold — refusing breaks the offline use case
that is this server's main reason to exist.

---

## 4. Phases

### Phase 0 — independent fixes, do first — **code complete**

H1 blocks testing anything else against real providers.

- [x] **H1** — `.env` is not loaded under any documented host config. `config.py:40` calls
      bare `load_dotenv()`, which walks up from CWD; an MCP server inherits the *host's*
      CWD. The three `docs/mcp/*.example.json` files set `command` but no `cwd`, so every
      keyed tool silently returns `missing_api_key`. Anchor the path
      (`Path.home() / ".threatsyft" / ".env"`) with a CWD-relative fallback. ~4 lines.
- [x] **H2** — pin `mcp[cli]>=1.28,<2`. `mcp` 2.0.0 (2026-07-28) is a major rework and the
      requirements are unpinned. Drop the `[cli]` extra — it pulls typer, rich, uvicorn,
      starlette, sse-starlette, python-multipart, PyJWT and cryptography for stdio servers
      that use none of them. Pin the other 7 deps.
      - [ ] Verify `mcp.server.fastmcp.FastMCP` survives into 2.0.0 —
            `py.sdk.modelcontextprotocol.io/migration/`. Still unverified. The `<2` pin
            makes this non-urgent: it is only needed before raising the upper bound.
- [x] **H5** — atomic snapshot writes. All four updaters `write_text` straight onto the
      live path (`update_attack.py:73`, `update_kev.py:73`, `update_lolbas.py:73`,
      `update_d3fend.py:65`). A crash mid-write leaves truncated JSON and every lookup fails
      until the update is re-run. Matters because ATT&CK is 47 MB. Write to `.tmp`, then
      `os.replace()`.

### Phase 1 — extract research to net-razor

Removes a whole trust class and the only remaining critical finding.

**Corrections to this phase as originally written**, from reading the tree on 2026-08-09:

1. There is no `reference/` package. The package on disk is `knowledge/`, and the
   `knowledge` → `reference` rename appears as a work item in no phase. `iocs.py` therefore
   lands at **`knowledge/iocs.py`**, and the rename moves to Phase 3 where that server's
   surface changes anyway. See the new Phase 3 bullet.
2. `tests/conftest.py` has an autouse fixture importing `research.url_validation`. Deleting
   that module breaks collection for the **whole** suite, not just research tests.
3. `research/iocs.py` had no tests of its own — its only coverage was incidental, via
   `test_research_articles.py` and `test_research_briefs.py`, both deleted here. Hence the
   1a/1b split: move and cover it *before* deleting the tests that were covering it.
4. The first two bullets are work in the **net-razor repo**, not this one. Nothing here
   imports them, so they do not block the deletion below. Track them in net-razor's own
   TODO. Note net-razor already has hn/yt/x sources — check for a generic RSS source before
   porting `feeds.py` rather than assuming a port is needed.
5. Six edits the original checklist missed, all in 1b below.

#### Phase 1a — move IOC extraction ahead of the deletion — **code complete**

- [x] `git mv research/iocs.py knowledge/iocs.py`, docstring retargeted off "research
      articles"; import updated in `articles.py:18`. No behaviour change.
- [x] Add `tests/test_iocs.py` (8 tests): all five IOC types, empty text, defang
      normalisation, case/trailing-punctuation normalisation, invalid dotted quads dropped,
      `MAX_CONTEXTS_PER_IOC` and `MAX_ITEMS_PER_TYPE` caps, context-window shape. The caps
      and the invalid-IP path had no coverage before, direct or incidental.
- [x] Move `iocs.py` under `knowledge/` in the README repo tree.

#### Phase 1b — delete research — **code complete**

- [x] Delete `research/feeds.py` (364), `research/articles.py` (255), `research/briefs.py`
      (237), `research/url_validation.py` (81), `research/__init__.py`, and the package
      directory; `mcp/research_server.py` (71).
- [x] Delete `tests/test_research_feeds.py` (209), `test_research_articles.py` (121),
      `test_research_briefs.py` (175), `test_research_mcp_server.py` (15).
- [x] Remove the autouse `stub_dns_resolution` fixture from `tests/conftest.py` — see
      correction 2. This is the item that breaks the suite if missed.
- [x] Reshape `extract_iocs` per §3.6 and **expose it as a tool on the knowledge server**.
      Decided 2026-08-09 to pull this forward from Phase 3: the fetch → extract → enrich
      flow in §2 needs the extract node the moment research leaves, and net-razor's fetch
      tool is the other half of it. Otherwise the module is dead code across two phases.
      Safe to reshape here because its only consumer, `articles.py`, dies in the same
      change. Rewrites the shape assertions in `tests/test_iocs.py`.
- [x] Remove the `threatsyft-research-mcp` script, its `.vscode/mcp.json` block and its
      entry in all three `docs/mcp/*.example.json`.
- [x] Remove `THREATSYFT_RESEARCH_FEEDS` and `THREATSYFT_RESEARCH_USER_AGENT` from
      `config.py` (including `DEFAULT_RESEARCH_*` and the `_split_research_feeds` helper at
      `:252`), `.env.example` and the README. Takes **L2** (malformed CISA feed URL in the
      example) with it.
- [x] Update `test_packaging.py` — it asserts all three server keys, in both tests.
- [x] `tests/test_mcp_stdio_launch.py:14` — drop `research_server` from `SERVER_MODULES`.
- [x] `tests/test_config.py:41-85` — delete the four `get_research_feeds` tests.
- [x] `knowledge/status.py:74` — drop `"research feed configuration"` from
      `does_not_report`; it is a caveat about a server that will not exist. No test asserts
      it.
- [x] `mcp/knowledge_server.py:35-36` — instructions tell the model to "use the research
      server for current public reporting". Reword.
- [x] `core.py:6` — docstring says the envelope lives at top level because knowledge and
      research both depend on it.
- [x] Strip the research sections from `README.md` (~20 references, including a full tool
      section and the repo tree), `ARCHITECTURE.md` (`:14`, `:57-71`, `:132-146`, `:156`,
      including the `research_attack_cluster` roadmap item) and `AGENTS.md` (`:7`, `:29`).
      Phase 4 keeps the deeper rewrite — the "deterministic" language and the AGENTS.md
      verdict principle — but the docs must not describe a deleted server for three phases.

**Closes by deletion:** C2 (critical — SSRF fail-open on DNS resolution failure), M3 (no
wire-level size cap, no content-type allowlist), M5 (redirects not followed, empty article
returned as success), L2, the `research_brief` double-fetch, and the research half of H9.

### Phase 2 — collapse enrichment to `enrich()`

- [ ] Promote `alienvault.py:34` `_classify_indicator` to shared code. It already does the
      full four-way split, which is why AlienVault is one tool instead of four — the
      existence proof for this whole collapse. Supporting pieces exist at `models.py:108`
      `classify_target`, `models.py:94` `is_file_hash`, `models.py:71` `normalize_url`.
- [ ] Add the dispatch table — data, not logic, ~30 lines:

      ip     → abuseipdb, greynoise, virustotal, shodan, ipgeolocation, alienvault,
               rdap, whois
      domain → dns, rdap, whois, virustotal, securitytrails, alienvault
      url    → google_safebrowsing, virustotal, alienvault
      hash   → virustotal, alienvault

- [ ] Reuse `aggregate.run_providers` unchanged — concurrent fan-out, fixed ordering.
- [ ] Implement the §3.2 `sources` shape; retire `provider_results`/`provider_errors`.
- [ ] **H7** — drop `overall_verdict` and `confidence`. Verified: same IP, same providers,
      VirusTotal returning `malicious` vs a 429 → verdict flips `malicious`/`high` to
      `suspicious`/`medium` with no marker on the verdict. Also treats four partly-shared
      feeds as four independent votes. Deletes ~120 lines and an untested heuristic.
- [ ] Delete `ip_reputation.py` (180), `domain_reputation.py` (170), `url_reputation.py`
      (149), `file_reputation.py` (138).
- [ ] **Retire the CLI.** Keep one `threatsyft-update <attack|kev|lolbas|all>` console
      script (~50 lines) reusing the existing `update_*` functions — snapshot updates have
      nowhere else to live, and making them an MCP tool would break the read-only posture.
      - [ ] Delete the `ip`/`domain`/`url`/`file`, `doctor`, `tools` and `smoke` commands.
            `enrichment_status` covers what `doctor` reported; `smoke` becomes an opt-in
            integration test.
      - [ ] Delete `cli.py` (372 less the retained ~50), `main.py` (25),
            `tests/test_cli.py` (303).
      - [ ] Delete `TOOL_CATALOG` (~220) with the `tools` command that was its only
            consumer — **keep `PROVIDERS`**, `enrichment_status` shares it. Closes **L3**.
      - [ ] `pyproject.toml`: drop `threatsyft`, add `threatsyft-update`. Update
            `test_packaging.py`.
      - [ ] Nothing to salvage from `--compact` — it projected results to a short status
            summary for terminal readability (`cli.py:292-305`). §3.7 solves response size
            by trimming defaults instead, so the projectors have no successor.

### Phase 3 — collapse reference to `lookup()` + `search()`

- [ ] **Drop D3FEND.** Delete `knowledge/d3fend.py` (574), `knowledge/update_d3fend.py`
      (137), `tests/test_d3fend_knowledge.py` (116), `tests/test_d3fend_update.py` (87).
      Remove `THREATSYFT_D3FEND_PATH` and the three `THREATSYFT_D3FEND_*_URL` vars. Halves
      server memory: ~440 MB peak → ~220 MB.
- [ ] `lookup(reference)` dispatch:

      CVE-####-#####  → nvd (cve_lookup), kev
      T####[.###]     → attack, lolbas search
      other           → lolbas by name

      Classifiers exist: `cve.py:128` `normalize_cve_id`, `attack.py:499`
      `normalize_technique_id`.
- [ ] `search(query, source="all", limit=10)` per §3.5.
- [ ] Delete `knowledge/briefs.py` (245) — `technique_brief` and `vulnerability_brief` are
      hand-written instances of exactly this dispatch pattern.
- [ ] Implement §3.7 payload trimming and §3.8 freshness metadata.
- [x] ~~Move `extract_iocs(text)` onto this server.~~ Pulled forward to Phase 1b — see the
      decision recorded there. Trust class fits: no keys, no metered calls.
- [ ] **Rename `knowledge/` → `reference/`**, `knowledge_server.py` → `reference_server.py`,
      `knowledge_status` → `reference_status`, and the `threatsyft-knowledge-mcp` script to
      `threatsyft-reference-mcp`. Added 2026-08-09: §1 names the server
      `threatsyft-reference` but no phase carried the rename, and Phase 1 assumed a
      `reference/` package that does not exist. Do it here, where the tool surface is
      already being rewritten, not in a deletion commit. Touches `.vscode/mcp.json`, all
      three `docs/mcp/*.example.json`, `pyproject.toml`, `test_packaging.py`,
      `test_mcp_stdio_launch.py` and the docs.
- [ ] **First-run bootstrap.** A fresh install has no `~/.threatsyft/`, so every reference
      tool fails until a ~49 MB download (post-D3FEND). Do **not** auto-download — a
      surprise 49 MB fetch triggered by a tool call is worse than a clear error. Do **not**
      ship snapshots in the repo — they go stale and bloat the package. Instead:
      - [ ] State the setup command in the server `instructions` string, so the model sees
            it at connect time rather than discovering it through a failed call.
      - [ ] Keep `details.setup_command` on the `not_found` error, which is already there
            and already correct (`attack.py:208`).

### Phase 4 — cleanup

- [ ] **H6** — document the envelope as the single error channel in each server's
      `instructions`. `ok:false` currently arrives as a protocol-level *success*; only
      raised exceptions set `isError`. Two channels that can disagree, and which one the
      client sees depends on the host. ~20 tokens. The alternative — raising `ToolError`
      for real failures — discards the structured `code` field, the most useful thing in
      the design.
- [ ] **H3b** — set tool annotations. Nothing sets them today. `threatsyft-reference` is
      read-only / idempotent / closed-world; `threatsyft-enrichment` is read-only /
      non-idempotent / open-world. It is the signal hosts use to decide what to
      auto-approve. ~4 lines per server.
- [ ] Declare real `outputSchema`s or none. Every tool currently declares
      `{additionalProperties: true, type: object}` — the null constraint, ~1,081 tokens
      across the surface to say nothing.
- [ ] **H11** — per-tool timeout budget. `dns.py:32-41` sets `resolver.lifetime = timeout`
      then resolves five record types **sequentially**, so 15s is per-record and worst case
      is 75s — longer than typical MCP host timeouts. `whois.py:44` calls `whois.whois()`
      with no `timeout` argument, so domain WHOIS ignores the setting entirely and uses
      python-whois's own 10s-per-socket default, accumulating per referral hop.
- [ ] **M6** — test that no API key value appears in any MCP tool response.
      `enrichment_status` asserts `secret_values_returned: false` at `status.py:66` as a
      self-declared flag with nothing behind it. Keys do not leak today, but only because
      httpx's `RequestError` messages happen not to include the URL — not a control this
      code owns.
- [ ] **H10** — document bare console scripts as the default launch path, absolute venv
      path as the fallback. Widest host support.
- [ ] **M9** — lockfile, after H2's pins land.
- [ ] **L1** — `.gitignore:41-44` ignores `data/knowledge/*` paths the code never uses.
- [ ] **L6** — `.venv/bin/` hardcoded across `.vscode/*.json`; wrong on Windows.
- [ ] **L7** — `rdap.py:24` hardcodes `RDAP_BASE_URL`; every other provider base URL is
      env-overridable, so RDAP is the one provider that cannot be pointed at a test double.
- [ ] **Audit the URL config surface.** Raised 2026-08-09 asking why URLs live in
      `config.py` rather than `.env`. Checked: they are not configuration, they are
      *defaults*. The pattern is `DEFAULT_X_URL` in `config.py` plus a getter reading
      `os.getenv("THREATSYFT_X_URL", DEFAULT_X_URL)`, so every one is already
      env-overridable, and the constant is what makes a fresh install work with no `.env`
      at all. Moving the values into `.env` would mean a clean checkout could not download
      ATT&CK until the user filled one in. Keep the pattern. Two real gaps behind the
      question:
      - [ ] Eight provider base URLs — `THREATSYFT_{ABUSEIPDB,ALIENVAULT,
            GOOGLE_SAFEBROWSING,GREYNOISE,IPGEOLOCATION,SECURITYTRAILS,SHODAN,
            VIRUSTOTAL}_BASE_URL` — are overridable in code but appear in **neither**
            `.env.example` **nor** the README config list. Only `NVD_BASE_URL` is
            documented. Either document all eight or delete the unused overrides; an
            undocumented config surface is the worse of the two.
      - [ ] RDAP is the mirror image — see **L7** directly above. Fixing both together
            makes the rule uniform: every outbound base URL is overridable and documented.
- [ ] **L4** — no explicit mode on the snapshot directory. Low risk, public catalogs.
- [ ] Update `ARCHITECTURE.md` and `AGENTS.md`:
      - `AGENTS.md:19` — "Prefer small provider-specific tools before aggregate tools such
        as `ip_reputation`." Rewrite as a principle about **verdicts** rather than
        **aggregation**: parallel fetch is fine, scoring is not.
      - `ARCHITECTURE.md` — three-server topology, the research server section and the
        `research_attack_cluster` roadmap item all move to net-razor.
      - Retire "deterministic" throughout. Not a testable property against live APIs.
        Replace with "fixed source ordering" (true, already implemented at
        `aggregate.py:39`).

---

## 5. Test strategy

~1,070 lines of tests are deleted alongside their code. The new dispatch tables are the
only genuinely new logic, and they are exactly the kind of thing that silently routes an
indicator to the wrong source set.

- [ ] **Dispatch tables are pure data — assert them directly.** One test per indicator type
      mapping to its expected source set. Cheap, and catches a reordered or dropped entry.
- [ ] **Assert every source named in a dispatch table actually exists** and is callable.
      Catches typos, which a dict of strings will otherwise hide until runtime.
- [ ] **Assert every indicator type has at least one source.** Prevents a type that
      classifies successfully then returns nothing.
- [ ] **One envelope-shape test per tool** with all sources stubbed: `sources` keyed
      correctly, `source_summary` counts matching, `indicator_type` echoed.
- [ ] **One test per §3.3 row** — the `ok` semantics table is a contract and should fail
      loudly if it drifts.
- [ ] **Keep every provider-level test.** They cover code that survives untouched.
- [ ] Delete tests only in the same commit as their code, never ahead of it.
- [ ] Retain the hermetic default — no live network in the unit suite. `smoke` becomes an
      opt-in integration test rather than a shipped command.

---

## 6. Closed as won't-do

**C1 — quota tracking / per-provider budgets.** Decided 2026-08-09. A `quota.py`
implementing local budgets was written and reverted the same day.

- It required a table of per-provider free-tier limits — exactly the free-versus-paid
  bookkeeping this project does not want to own, and it needed overriding for any paid plan.
- Its strongest justification was the injection amplification path, where a hostile page
  emits up to 50 pivots and an agent works the list. That path leaves with the research
  server in Phase 1.
- The behaviour it protected already exists. `enrichment/http.py:65-88` maps a provider 429
  to a `rate_limited` envelope; `run_providers` records it as one source error and returns
  everything else. Running out of credit degrades to less data, clearly attributed, with no
  new code.

**Accepted consequence:** nothing stops a hot retry loop from repeatedly hitting a provider
that is already refusing it. That is a bug in the calling graph and the retry policy belongs
there — the same argument as the injection controls belonging in the consuming agent.

---

## 7. Deferred

- [ ] **Response cache** — content-addressed, per-provider TTL, ~80–120 lines. Now purely a
      latency win and a fixture source, not a safety control. Freshness cost: 1h TTL on
      reputation data, 24h on WHOIS/RDAP/geolocation.
- [ ] **M2** — per-source `as_of` and a cached/live marker. Mandatory once the cache lands,
      pointless before it.
- [ ] **M4** — end-to-end reproducibility tests off the cache's fixtures. Mostly moot once
      H7 removes the aggregate verdict.
- [ ] **M10** — ~220 MB RSS post-D3FEND. Only worth attention if memory becomes a real
      constraint.
- [ ] **M11** — evaluate whether a model picks the right tool for realistic analyst queries.
      **Last.** Measuring selection accuracy against a surface about to go 38 → 6 would
      measure the wrong thing.

---

## 8. Open questions

- [ ] **Octal IP handling under glibc.** `0177.0.0.1` was allowed during review because
      macOS `getaddrinfo` resolves it to the public 177.0.0.1. Linux may differ. Moot once
      Phase 1 removes all URL validation — carried only in case a fetcher ever returns.
