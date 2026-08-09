"""Keep API keys out of logs.

Some provider APIs take the key as a URL query parameter rather than a header:
Shodan uses ``?key=``, IPGeolocation uses ``?apiKey=``, Google Safe Browsing
uses ``?key=``. httpx logs the full request URL at INFO level, so making a
request writes those keys to stderr, which an MCP host captures into its logs.

Note that httpx's *error* messages omit the URL, so error handling alone is not
evidence that keys are safe; ordinary request logging is the exposure.

Two layers, because the first depends on a log level nobody controls:

1. httpx's request logger is quietened, which removes the known leak.
2. A filter redacts key-bearing query parameters from every log record, so a
   future library that logs a URL cannot reintroduce this.
"""

from __future__ import annotations

import logging
import re

# Query parameters whose values are credentials. Matched case-insensitively
# against the whole record, including the exception text.
SECRET_QUERY_PARAMS = ("key", "apikey", "api_key", "token", "auth", "password")

_SECRET_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(SECRET_QUERY_PARAMS) + r")=([^&\s\"'<>]+)",
)
REDACTED = r"\1=[REDACTED]"


class RedactSecretsFilter(logging.Filter):
    """Strip credential-bearing query parameters from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(
                redact(arg) if isinstance(arg, str) else arg for arg in _as_tuple(record.args)
            )
        return True


def _as_tuple(args: object) -> tuple:
    return args if isinstance(args, tuple) else (args,)


def redact(value: str) -> str:
    """Replace the value of any credential-bearing query parameter."""
    return _SECRET_PATTERN.sub(REDACTED, value)


def configure_logging() -> None:
    """Silence request-level HTTP logging and redact secrets from what remains.

    Called from every entry point. Cheap and idempotent, so calling it twice is
    harmless.
    """
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    secrets_filter = RedactSecretsFilter()
    root = logging.getLogger()
    if not any(isinstance(existing, RedactSecretsFilter) for existing in root.filters):
        root.addFilter(secrets_filter)
    for handler in root.handlers:
        if not any(isinstance(existing, RedactSecretsFilter) for existing in handler.filters):
            handler.addFilter(secrets_filter)
