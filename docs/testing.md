# End-to-end testing checklist

The automated suite is hermetic: it never touches the network and never reads a
real snapshot. That is deliberate, and it means a whole class of problem is
invisible to it. Every bug found in this project since the rework came from
running the thing rather than from a unit test — blank environment variables
wiping every URL, a setup command naming a retired CLI, API keys reaching stderr
through request logging, a 44 KB response.

This is what to check by hand, and what to ask an agent.

---

## 1. Setup states

Work through these in order. Each one is a state a new user can actually be in.

| State | How to produce it | Expected |
|---|---|---|
| Nothing configured | No `~/.threatsyft/.env`, no snapshots | Servers start. `lookup` returns `ok: true` with every source `not_found` and a `details.setup_command`. `enrich` returns `ok: true` with RDAP and WHOIS data and `missing_api_key` for the rest. |
| Snapshots, no keys | `threatsyft-update all`, no `.env` | `lookup` and `search` fully work. `enrich` still returns RDAP/WHOIS. |
| Keys, no snapshots | `.env` present, `~/.threatsyft/knowledge` removed | `enrich` fully works. `lookup` reports `not_found` with `snapshot_present: false`. |
| Fully configured | Both | Everything returns data. |
| Stale snapshot | `touch -t 202401010000 ~/.threatsyft/knowledge/cisa/*.json` | KEV results carry `freshness.stale: true` and an `age_days` in the hundreds. Results still return. |

The stale case matters most. "This CVE is not in KEV" reads as "not known to be
exploited", and on a year-old catalog that claim is wrong.

## 2. Launch and protocol

- [ ] Both servers appear in your MCP host after a reload, with 2 and 4 tools.
- [ ] Start each from a directory that is **not** the repo. `.env` must still be
      found, because MCP hosts set their own working directory.
- [ ] Check the host's server log for `HTTP Request:` lines. There should be
      none. Two provider APIs pass the key in the URL, so request logging is a
      credential leak.
- [ ] Confirm tool annotations reach the host: knowledge read-only/idempotent/
      closed-world, enrichment read-only/non-idempotent/open-world.

## 3. Response size

Watch for responses that blow a context budget. Rough expectations on real data:

| Call | Expected |
|---|---|
| `lookup("T1059")` | ~10 KB |
| `lookup("TA0002")` | ~11 KB |
| `enrich("8.8.8.8")` | ~7 KB |
| `enrich("example.com")` | ~8 KB |
| `search("powershell")` | ~7 KB |

Anything above ~15 KB deserves a look at which source is responsible. Both
oversized payloads found so far came from a list nobody had capped.

## 4. Agent prompts

The point is whether a model picks the right tool from six, unprompted. Ask
these without naming the tool, then check which was called.

**Should reach `enrich`:**
- "What do you know about 8.8.8.8?"
- "Is example.com suspicious?"
- "Check this hash: d41d8cd98f00b204e9800998ecf8427e"

**Should reach `lookup`:**
- "What is T1059?"
- "Tell me about CVE-2021-44228 — is it being exploited?"
- "What does APT29 do?"
- "What is certutil.exe abused for?"

**Should reach `search`:**
- "What ATT&CK techniques involve PowerShell?"
- "Which known-exploited vulnerabilities mention MOVEit?"

**Should reach `extract_iocs`:**
- "Pull the indicators out of this note: <paste text with defanged IOCs>"

**Should self-correct:**
- "Enrich CVE-2021-44228" — `enrich` refuses and names `lookup`. Does the agent
  follow the redirect without being told?
- "Look up 8.8.8.8" — the mirror image, pointing at `enrich`.

**Should not happen:**
- The agent treating `ok: true` with every source failed as a successful answer.
  Ask about an IP with no keys configured and see whether it says "nothing was
  found" (wrong) or "no source could answer" (right).
- The agent inventing a verdict. `enrich` deliberately returns none. Ask "is this
  IP malicious?" and check it reasons from the per-source data rather than
  claiming the tool said so.

## 5. Failure injection

- [ ] Corrupt a snapshot (`echo "{" > ~/.threatsyft/knowledge/cisa/*.json`).
      Expect `parse_error` for that source, others unaffected. Restore with
      `threatsyft-update kev`.
- [ ] Put a bad API key in `.env`. Expect `authentication_error` for that source
      only, and the call still `ok: true`.
- [ ] Set `THREATSYFT_TIMEOUT_SECONDS=0.001`. Expect `timeout` codes rather than
      a hang.
- [ ] Point a base URL at something dead
      (`THREATSYFT_ABUSEIPDB_BASE_URL=https://127.0.0.1:9`). Expect
      `network_error` for that source alone.

## 6. Before trusting a release

- [ ] `.venv/bin/python -m pytest` — all green
- [ ] `.venv/bin/ruff check .` and `ruff format --check src tests`
- [ ] Setup states 1 and 5 above, at minimum
- [ ] Grep the host log for `HTTP Request:` and for any key value from `.env`
