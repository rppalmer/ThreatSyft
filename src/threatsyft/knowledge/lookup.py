"""Single-call reference lookup and search across the local knowledge sources.

Collection, not judgement, and the same ``sources`` shape ``enrich`` returns, so
a caller written against one iterates the other unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, NamedTuple

from threatsyft.core import InputValidationError, build_sources, error_response, success_response

# Importing the indicator classifier is not a boundary violation: the strict
# boundary in this design is MCP-to-MCP, and models.py is pure validation with
# no keys, no network and no provider imports. Reimplementing IP/URL/hash
# detection here would be more code and would drift.
from threatsyft.enrichment.models import classify_indicator
from threatsyft.fanout import run_sources
from threatsyft.knowledge.attack import (
    attack_actor_lookup,
    attack_actor_search,
    attack_mitigation_lookup,
    attack_software_lookup,
    attack_tactic_lookup,
    attack_technique_lookup,
    normalize_technique_id,
)
from threatsyft.knowledge.attack import attack_search as run_attack_search
from threatsyft.knowledge.cve import cve_lookup, normalize_cve_id
from threatsyft.knowledge.freshness import snapshot_freshness
from threatsyft.knowledge.kev import kev_lookup
from threatsyft.knowledge.kev import kev_search as run_kev_search
from threatsyft.knowledge.lolbas import lolbas_lookup
from threatsyft.knowledge.lolbas import lolbas_search as run_lolbas_search

LOOKUP_TOOL_NAME = "lookup"
SEARCH_TOOL_NAME = "search"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TACTIC_PATTERN = re.compile(r"^TA\d{4}$", re.IGNORECASE)
MITIGATION_PATTERN = re.compile(r"^M\d{4}$", re.IGNORECASE)
ACTOR_PATTERN = re.compile(r"^G\d{4}$", re.IGNORECASE)
SOFTWARE_PATTERN = re.compile(r"^S\d{4}$", re.IGNORECASE)

# How many LOLBAS hits to attach when looking up an ATT&CK technique. This is a
# supporting cross-reference, not the answer, so it stays small.
TECHNIQUE_LOLBAS_LIMIT = 5

SEARCH_SOURCES = {
    "attack_technique": run_attack_search,
    "attack_actor": attack_actor_search,
    "kev": run_kev_search,
    "lolbas": run_lolbas_search,
}

SourceFunction = tuple[str, Callable[[str], dict[str, Any]]]


class ReferenceType(NamedTuple):
    """One kind of reference `lookup` recognises, and what answers it."""

    name: str
    # None matches anything, which is how the bare-name fallback is expressed.
    pattern: re.Pattern[str] | None
    normalize: Callable[[str], str]
    sources: tuple[SourceFunction, ...]


# Tried in order, first match wins. Data rather than a chain of if-statements so
# the set of source names a lookup can produce is enumerable: `test_freshness`
# derives its expectation from this table, so a source added here cannot
# silently arrive without its snapshot age. `enrich.DISPATCH` and
# `SEARCH_SOURCES` are tables for the same reason.
REFERENCE_TYPES: tuple[ReferenceType, ...] = (
    ReferenceType(
        "cve",
        CVE_PATTERN,
        normalize_cve_id,
        (("nvd", cve_lookup), ("kev", kev_lookup)),
    ),
    ReferenceType(
        "attack_tactic",
        TACTIC_PATTERN,
        str.upper,
        (("attack_tactic", attack_tactic_lookup),),
    ),
    ReferenceType(
        "attack_mitigation",
        MITIGATION_PATTERN,
        str.upper,
        (("attack_mitigation", attack_mitigation_lookup),),
    ),
    ReferenceType(
        "attack_actor",
        ACTOR_PATTERN,
        str.upper,
        (("attack_actor", attack_actor_lookup),),
    ),
    ReferenceType(
        "attack_software",
        SOFTWARE_PATTERN,
        str.upper,
        (("attack_software", attack_software_lookup),),
    ),
    ReferenceType(
        "attack_technique",
        TECHNIQUE_PATTERN,
        normalize_technique_id,
        (
            ("attack_technique", attack_technique_lookup),
            ("lolbas", lambda value: run_lolbas_search(value, TECHNIQUE_LOLBAS_LIMIT)),
        ),
    ),
    # A bare name could be a LOLBAS binary ("Certutil.exe"), an ATT&CK tactic
    # ("execution") or a threat actor ("APT29", "Cozy Bear"), and telling them
    # apart up front would mean guessing. Ask all three instead: they are local,
    # fast, and whichever knows the name answers. That is the same principle the
    # rest of the design follows - collect from every source that might have it
    # and let the caller see which one did.
    ReferenceType(
        "name",
        None,
        str,
        (
            ("lolbas", lolbas_lookup),
            ("attack_tactic", attack_tactic_lookup),
            ("attack_actor", attack_actor_lookup),
        ),
    ),
)

LOOKUP_SOURCE_NAMES = {name for reference in REFERENCE_TYPES for name, _ in reference.sources}


def lookup(reference: str) -> dict[str, Any]:
    """Classify one reference and collect every local source that covers it."""
    query = {"reference": reference}
    value = reference.strip()
    if not value:
        return error_response(
            LOOKUP_TOOL_NAME, query, "invalid_input", "Reference must not be empty."
        )

    redirect = _wrong_tool_error(value, query)
    if redirect:
        return redirect

    try:
        reference_type, normalized, sources = _classify_reference(value)
    except InputValidationError as exc:
        return error_response(LOOKUP_TOOL_NAME, query, "invalid_input", str(exc))

    query["reference"] = normalized
    source_entries, summary = build_sources(run_sources(sources, normalized))
    _attach_freshness(source_entries)

    return success_response(
        LOOKUP_TOOL_NAME,
        query,
        {
            "reference": normalized,
            "reference_type": reference_type,
            "source_summary": summary,
            "sources": source_entries,
        },
    )


def search(query: str, source: str = "all", limit: int = 10) -> dict[str, Any]:
    """Search the local catalogs, grouped by source and never merge-ranked.

    ATT&CK techniques, KEV entries and LOLBAS binaries share almost no fields,
    and their three scoring functions produce numbers on unrelated scales.
    Merging them into one ranked list would invent a precision that does not
    exist, so results stay grouped by source.

    ``limit`` applies per source, so ``source="all"`` does not silently return
    three times the requested rows.
    """
    response_query: dict[str, Any] = {"query": query, "source": source, "limit": limit}

    if not query.strip():
        return error_response(
            SEARCH_TOOL_NAME, response_query, "invalid_input", "Search query must not be empty."
        )

    selected = _selected_sources(source)
    if selected is None:
        return error_response(
            SEARCH_TOOL_NAME,
            response_query,
            "invalid_input",
            f"Source must be one of: all, {', '.join(SEARCH_SOURCES)}.",
            {"valid_sources": ["all", *SEARCH_SOURCES]},
        )

    results = [(name, SEARCH_SOURCES[name](query, limit)) for name in selected]
    source_entries, summary = build_sources(results)

    # Lift the per-source counts up beside the matches so a caller can see how
    # much it is not being shown without reaching into each source's payload.
    for entry in source_entries.values():
        if entry["ok"]:
            data = entry.pop("data")
            entry["match_count"] = data.get("match_count", 0)
            entry["returned"] = data.get("returned", len(data.get("matches", [])))
            entry["matches"] = data.get("matches", [])

    _attach_freshness(source_entries)

    return success_response(
        SEARCH_TOOL_NAME,
        response_query,
        {
            "query": query.strip(),
            "source_summary": summary,
            "sources": source_entries,
        },
    )


def _attach_freshness(source_entries: dict[str, dict[str, Any]]) -> None:
    """Stamp each snapshot-backed source with how old its data is.

    Applied to failures as much as successes. "Not in KEV" from a catalog that
    stopped refreshing months ago is the case this exists for, and that arrives
    as a not_found, not as a success.
    """
    for name, entry in source_entries.items():
        freshness = snapshot_freshness(name)
        if freshness is not None:
            entry["freshness"] = freshness


def _classify_reference(value: str) -> tuple[str, str, tuple[SourceFunction, ...]]:
    """Return the reference type, its normalized form, and the sources covering it."""
    for reference in REFERENCE_TYPES:
        if reference.pattern is None or reference.pattern.fullmatch(value):
            return reference.name, reference.normalize(value), reference.sources

    raise AssertionError("REFERENCE_TYPES must end with a row that matches anything.")


def _selected_sources(source: str) -> list[str] | None:
    normalized = source.strip().lower()
    if normalized in {"", "all"}:
        return list(SEARCH_SOURCES)
    if normalized in SEARCH_SOURCES:
        return [normalized]
    return None


def _wrong_tool_error(value: str, query: dict[str, Any]) -> dict[str, Any] | None:
    """Point an enrichable indicator at the tool that handles it.

    The symmetric case of ``enrich``'s redirect: a caller that reached for the
    wrong one of the two collection tools gets told which one is right, rather
    than an unhelpful "not found".
    """
    if CVE_PATTERN.fullmatch(value) or TECHNIQUE_PATTERN.fullmatch(value):
        return None

    try:
        indicator_type, _ = classify_indicator(value)
    except InputValidationError:
        return None

    if indicator_type == "domain":
        # A LOLBAS binary name looks enough like a domain that rejecting it here
        # would break the tool's main case. Let the lolbas lookup answer.
        return None

    return error_response(
        LOOKUP_TOOL_NAME,
        query,
        "invalid_input",
        f"{value} is an enrichable indicator, not a reference.",
        {"detected_type": indicator_type, "suggested_tool": "enrich"},
    )
