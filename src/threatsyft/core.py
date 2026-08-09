"""Shared tool response envelope and error types.

This is the project-wide contract every MCP tool speaks: the stable
``{ok, tool, query, data, error}`` envelope and the ``InputValidationError``
raised during input validation. It lives in a neutral top-level module rather
than under ``enrichment/`` because the knowledge tools depend on it just as much
as enrichment does.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, Field

ErrorCode = Literal[
    "invalid_input",
    "not_found",
    "timeout",
    "network_error",
    "upstream_error",
    "parse_error",
    "missing_api_key",
    "authentication_error",
    "rate_limited",
    "unsupported_target",
    "unexpected_error",
]


class InputValidationError(ValueError):
    """Raised when a tool input cannot be safely handled."""


class ToolError(BaseModel):
    """Structured error returned by a tool."""

    code: ErrorCode
    message: str
    details: dict[str, Any] | str | None = None


class ToolResponse(BaseModel):
    """Stable response envelope for MCP tool results."""

    ok: bool
    tool: str
    query: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] | None = None
    error: ToolError | None = None


def build_sources(
    results: Iterable[tuple[str, dict[str, Any]]],
) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
    """Build the shared ``sources`` map and its summary from source envelopes.

    One shape for every collection tool, so a caller written against ``enrich``
    iterates ``lookup`` and ``search`` unchanged. Every entry looks the same
    whether the source succeeded or not, which is what lets a consumer iterate
    one structure instead of correlating a results map against an errors list.

    ``source_summary`` exists so a node can answer "did anything work?" without
    iterating at all.
    """
    sources: dict[str, dict[str, Any]] = {}
    for name, envelope in results:
        if envelope.get("ok") is True and isinstance(envelope.get("data"), dict):
            sources[name] = {"ok": True, "data": envelope["data"]}
            continue

        error = envelope.get("error") if isinstance(envelope.get("error"), dict) else {}
        entry = {
            "ok": False,
            "code": error.get("code", "unexpected_error"),
            "message": error.get("message", "Source lookup failed."),
        }
        # Carry details through when a source provides them. This is where
        # `setup_command` lives on a missing snapshot, which is the one piece of
        # the response that tells a caller how to fix the problem; dropping it
        # left "snapshot not found" with no way to act on it.
        details = error.get("details")
        if details:
            entry["details"] = details
        sources[name] = entry

    succeeded = sum(1 for entry in sources.values() if entry["ok"])
    return sources, {"ok": succeeded, "failed": len(sources) - succeeded}


def success_response(tool: str, query: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """Build a successful tool response."""
    return ToolResponse(ok=True, tool=tool, query=query, data=data).model_dump(mode="json")


def error_response(
    tool: str,
    query: dict[str, Any],
    code: ErrorCode,
    message: str,
    details: dict[str, Any] | str | None = None,
) -> dict[str, Any]:
    """Build a failed tool response."""
    error = ToolError(code=code, message=message, details=details)
    return ToolResponse(ok=False, tool=tool, query=query, error=error).model_dump(mode="json")
