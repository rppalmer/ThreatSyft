import io
import logging

import httpx
import pytest

from threatsyft.logging_setup import RedactSecretsFilter, configure_logging, redact

# The exact shapes that leaked, with placeholder values.
SHODAN_URL = "https://api.shodan.io/shodan/host/8.8.8.8?key=abc123SECRET&history=false"
IPGEO_URL = "https://api.ipgeolocation.io/v3/ipgeo?apiKey=def456SECRET&ip=8.8.8.8"


@pytest.fixture
def captured_root_output():
    """Capture everything that reaches the root handler, as a host's log would."""
    root = logging.getLogger()
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    original_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield buffer
    finally:
        root.removeHandler(handler)
        root.setLevel(original_level)


@pytest.fixture(autouse=True)
def restore_http_logging():
    """Leave the httpx/httpcore loggers as they were found."""
    names = ["httpx", "httpcore", "httpcore.connection"]
    saved = [
        (name, logging.getLogger(name).level, list(logging.getLogger(name).filters))
        for name in names
    ]
    yield
    for name, level, filters in saved:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.filters = filters


# --- the substitution itself --------------------------------------------------


def test_redacts_a_key_query_parameter() -> None:
    assert "abc123SECRET" not in redact(SHODAN_URL)
    assert "key=[REDACTED]" in redact(SHODAN_URL)


def test_redacts_an_apikey_query_parameter() -> None:
    assert "def456SECRET" not in redact(IPGEO_URL)


def test_keeps_the_rest_of_the_url_readable() -> None:
    """Redaction must not destroy the diagnostic value of the log line."""
    cleaned = redact(SHODAN_URL)

    assert "api.shodan.io" in cleaned
    assert "8.8.8.8" in cleaned
    assert "history=false" in cleaned


def test_leaves_a_url_without_credentials_alone() -> None:
    url = "https://rdap.org/ip/8.8.8.8"
    assert redact(url) == url


# --- what actually reaches a host's log ---------------------------------------


def test_configure_logging_quietens_httpx_request_logging() -> None:
    """The known leak: httpx logs full request URLs at INFO."""
    configure_logging()

    assert logging.getLogger("httpx").level >= logging.WARNING


def test_a_raised_httpx_level_still_does_not_leak_the_key(captured_root_output) -> None:
    """The second layer, asserted end to end rather than by inspecting filters.

    Quietening the logger is one setting away from being undone by a host that
    configures logging itself, so the record that survives must arrive redacted.
    """
    configure_logging()
    logging.getLogger("httpx").setLevel(logging.INFO)

    logging.getLogger("httpx").info('HTTP Request: GET %s "HTTP/1.1 200 OK"', SHODAN_URL)

    output = captured_root_output.getvalue()
    assert "abc123SECRET" not in output
    assert "api.shodan.io" in output, "redaction must not swallow the whole line"


def test_an_httpcore_child_logger_is_redacted_too(captured_root_output) -> None:
    """httpcore logs through children, which a filter on the parent never sees."""
    logging.getLogger("httpcore.connection")  # created by importing httpcore in practice
    configure_logging()
    logging.getLogger("httpcore.connection").setLevel(logging.DEBUG)

    logging.getLogger("httpcore.connection").debug("trace %s", IPGEO_URL)

    assert "def456SECRET" not in captured_root_output.getvalue()


def test_a_real_request_logs_no_key_at_info(captured_root_output, monkeypatch) -> None:
    """Drive httpx itself rather than imitating its log line."""
    configure_logging()
    logging.getLogger("httpx").setLevel(logging.INFO)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        client.get(SHODAN_URL)

    output = captured_root_output.getvalue()
    assert "abc123SECRET" not in output


def test_configure_logging_is_idempotent() -> None:
    configure_logging()
    configure_logging()

    filters = logging.getLogger("httpx").filters
    assert sum(isinstance(item, RedactSecretsFilter) for item in filters) == 1


def test_the_filter_redacts_a_secret_carried_by_a_non_string_argument() -> None:
    """httpx passes an httpx.URL, not a str. Imitate that with any non-str object."""

    class Url:
        def __str__(self) -> str:
            return SHODAN_URL

    record = logging.LogRecord("t", logging.INFO, __file__, 1, "%s %d", (Url(), 42), None)

    RedactSecretsFilter().filter(record)

    assert "abc123SECRET" not in record.getMessage()
    assert "42" in record.getMessage()


def test_the_filter_leaves_a_clean_record_untouched() -> None:
    args = ("https://rdap.org",)
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "GET %s", args, None)

    RedactSecretsFilter().filter(record)

    assert record.args == ("https://rdap.org",), "an unchanged record keeps its lazy formatting"


def test_configure_logging_quietens_mcp_request_logging() -> None:
    """The SDK logs a line per request; a stdio host shows that to the user."""
    logging.getLogger("mcp.server").setLevel(logging.NOTSET)

    configure_logging()

    assert logging.getLogger("mcp.server").level == logging.WARNING
    assert logging.getLogger("mcp.server.lowlevel.server").getEffectiveLevel() == (logging.WARNING)


def test_mcp_quietening_adds_no_redaction_filter() -> None:
    """Volume and credential exposure are separate concerns with separate lists."""
    configure_logging()

    filters = logging.getLogger("mcp.server").filters
    assert not any(isinstance(f, RedactSecretsFilter) for f in filters)
