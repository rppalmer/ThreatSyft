"""Passive DNS history for an IP address, from mnemonic's open API.

Fills the one gap left in the IP row: what else has been hosted at this address,
and when. Censys reports the DNS names resolving to a host right now, and
SecurityTrails covers the domain side, so nothing answered the historical
question. A shared-hosting address with a hundred unrelated domains and a
dedicated one with a single long-lived name look identical without it.

No API key. mnemonic serves this anonymously, which is why SecurityTrails is not
used here — its reverse-IP endpoint is a paid feature and the free tier answers
403.

What comes back is a slice, not a census. Records carry `tlp: white` and a
`partialResult` flag, and `count` saturates at 1000 rather than continuing to
climb, so a result at the cap means "at least this many" and the returned rows
are a sample of them. Both are reported rather than smoothed over.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from threatsyft.config import get_mnemonic_base_url, get_timeout_seconds
from threatsyft.enrichment.http import auth_or_rate_error, guarded_get, parse_json_object
from threatsyft.enrichment.models import (
    InputValidationError,
    error_response,
    normalize_ip,
    success_response,
)

UTC = ZoneInfo("UTC")

TOOL_NAME = "mnemonic_pdns_lookup"
PROVIDER = "mnemonic passive DNS"

# A busy address has thousands of names. Enough to see whether this is shared
# hosting or dedicated, without turning one source into the whole response.
MAX_RECORDS = 50

# The value `count` stops at, so a response sitting exactly here is a floor
# rather than a total.
COUNT_CAP = 1000


def mnemonic_pdns_lookup(ip: str) -> dict[str, Any]:
    """Look up passive DNS records observed for one IP address."""
    query = {"ip": ip}

    try:
        normalized_ip = normalize_ip(ip)
    except InputValidationError as exc:
        return error_response(TOOL_NAME, query, "invalid_input", str(exc))

    query["ip"] = normalized_ip
    url = f"{get_mnemonic_base_url()}/{normalized_ip}"

    result = guarded_get(
        TOOL_NAME,
        query,
        PROVIDER,
        lambda: httpx.get(
            url,
            params={"limit": MAX_RECORDS},
            headers={"Accept": "application/json"},
            timeout=get_timeout_seconds(),
        ),
    )
    if result.error:
        return result.error
    response = result.response

    auth_error = auth_or_rate_error(TOOL_NAME, query, PROVIDER, response)
    if auth_error:
        return auth_error

    parsed = parse_json_object(TOOL_NAME, query, PROVIDER, response)
    if parsed.error:
        return parsed.error
    payload = parsed.payload

    rows = payload.get("data")
    rows = rows if isinstance(rows, list) else []
    records = [_record(row) for row in rows[:MAX_RECORDS]]
    records = [record for record in records if record]
    # Most recently observed first, so the rows kept are the ones a triage
    # question is about. Only orders what this page returned; when `count` is at
    # the cap there are older names that were never sent.
    records.sort(key=lambda record: record.get("last_seen") or "", reverse=True)

    count = payload.get("count")
    return success_response(
        TOOL_NAME,
        query,
        {
            "ip": normalized_ip,
            "record_count": count,
            "record_count_is_capped": count == COUNT_CAP,
            "returned": len(records),
            "records": records,
            "source": "mnemonic",
            "source_url": "https://passivedns.mnemonic.no/",
            "note": (
                "Public passive DNS (TLP:WHITE, partial results). Names seen resolving "
                "to this address, not names currently resolving to it. Absence of a "
                "record is not evidence a name was never here."
            ),
        },
    )


def _record(row: Any) -> dict[str, Any]:
    """Reduce one passive DNS row to the name, the type, and the window it was seen in."""
    if not isinstance(row, dict):
        return {}

    record = {
        "domain": row.get("query"),
        "rrtype": row.get("rrtype"),
        # mnemonic exposes firstSeenTimestamp/lastSeenTimestamp too, but the open
        # tier leaves them zeroed; these two carry the real dates.
        "first_seen": _timestamp(row.get("createdTimestamp")),
        "last_seen": _timestamp(row.get("lastUpdatedTimestamp")),
        # How many times the resolution was observed. A name seen once is a very
        # different claim from one seen thousands of times.
        "observations": row.get("times"),
    }
    return {key: value for key, value in record.items() if value is not None}


def _timestamp(value: Any) -> str | None:
    """Convert epoch milliseconds to an ISO timestamp, treating zero as absent."""
    if not isinstance(value, int | float) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
