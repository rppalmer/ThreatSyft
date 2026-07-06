"""Shared tool response envelope and error types.

This is the project-wide contract every MCP tool speaks: the stable
``{ok, tool, query, data, error}`` envelope and the ``InputValidationError``
raised during input validation. It lives in a neutral top-level module rather
than under ``enrichment/`` because the knowledge and research tools depend on it
just as much as enrichment does.
"""

from __future__ import annotations

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
