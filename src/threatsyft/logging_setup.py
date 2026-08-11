"""Keep API keys out of logs.

Some provider APIs take the key as a URL query parameter rather than a header:
Shodan uses ``?key=``, IPGeolocation uses ``?apiKey=``, Google Safe Browsing
uses ``?key=``. httpx logs the full request URL at INFO level, so making a
request writes those keys to stderr, which an MCP host captures into its logs.

Note that httpx's *error* messages omit the URL, so error handling alone is not
evidence that keys are safe; ordinary request logging is the exposure.

Two layers, because the first depends on a level anyone can put back:

1. The HTTP libraries' loggers are quietened, which removes the known leak.
2. A redacting filter is attached to those same loggers, so if something raises
   the level again — a host that configures logging, a deliberate debug session
   — the URLs still come out without their credentials.

The filter goes on the HTTP loggers themselves, not on the root logger. A
logger's filters are applied only to records logged *through* that logger:
records propagating up from ``httpx`` never meet a filter installed on root, so
redacting there looks configured and does nothing. For the same reason the
filter is attached to httpcore's child loggers (``httpcore.connection`` and
friends) individually rather than to ``httpcore`` alone.
"""

from __future__ import annotations

import logging
import re

# Query parameters whose values are credentials. Matched case-insensitively
# against the record's formatted message.
SECRET_QUERY_PARAMS = ("key", "apikey", "api_key", "token", "auth", "password")

# The library namespaces that log request URLs.
URL_LOGGER_PREFIXES = ("httpx", "httpcore")

# Namespaces that are merely noisy. The MCP SDK logs a line per request at INFO,
# and FastMCP routes it to stderr through a rich handler. A stdio host reads
# stdout for the protocol and shows stderr to the user, so on an interactive
# host that lands in the middle of whatever the user is looking at. Separate
# from URL_LOGGER_PREFIXES because this is volume, not credential exposure: no
# redaction filter is wanted here, only a level.
NOISY_LOGGER_PREFIXES = ("mcp.server",)

_SECRET_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(SECRET_QUERY_PARAMS) + r")=([^&\s\"'<>]+)",
)
REDACTED = r"\1=[REDACTED]"


class RedactSecretsFilter(logging.Filter):
    """Strip credential-bearing query parameters from log records.

    The record is formatted here rather than having its ``msg`` and ``args``
    rewritten in place, because the secret usually is not a string at this
    point. httpx logs ``logger.info("HTTP Request: %s %s ...", method, url)``
    and passes an ``httpx.URL`` object, so a filter that only rewrites string
    arguments walks straight past the credential and the leak reappears when
    the handler formats the record later.

    Formatting early costs nothing on these loggers, which are quietened to
    WARNING, and the substitution only replaces the record when it changed
    something.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - a broken format string is not ours to fix
            return True

        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def redact(value: str) -> str:
    """Replace the value of any credential-bearing query parameter."""
    return _SECRET_PATTERN.sub(REDACTED, value)


def configure_logging() -> None:
    """Silence request-level HTTP and MCP logging, and redact what remains.

    Called from every entry point. Cheap and idempotent, so calling it twice is
    harmless.

    The levels are set on the library loggers themselves rather than on root,
    because FastMCP calls ``logging.basicConfig`` and owns root's level and
    handler; a level set there is whatever FastMCP last decided it should be.
    """
    for name in URL_LOGGER_PREFIXES + NOISY_LOGGER_PREFIXES:
        logging.getLogger(name).setLevel(logging.WARNING)

    for logger in _url_loggers():
        if not any(isinstance(existing, RedactSecretsFilter) for existing in logger.filters):
            logger.addFilter(RedactSecretsFilter())


def _url_loggers() -> list[logging.Logger]:
    """The URL-logging namespaces, plus any descendants already created.

    Descendants are found rather than named, because they belong to a
    third-party library: httpcore splits its logging across ``httpcore.http11``,
    ``httpcore.connection`` and others, and hard-coding that list would rot the
    next time it changes.
    """
    loggers = [logging.getLogger(name) for name in URL_LOGGER_PREFIXES]
    for name, existing in list(logging.root.manager.loggerDict.items()):
        if not isinstance(existing, logging.Logger):
            continue
        if any(name.startswith(f"{prefix}.") for prefix in URL_LOGGER_PREFIXES):
            loggers.append(existing)
    return loggers
