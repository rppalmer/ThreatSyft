import logging

from threatsyft.logging_setup import RedactSecretsFilter, configure_logging, redact

# The exact shapes that leaked, with placeholder values.
SHODAN_URL = "https://api.shodan.io/shodan/host/8.8.8.8?key=abc123SECRET&history=false"
IPGEO_URL = "https://api.ipgeolocation.io/v3/ipgeo?apiKey=def456SECRET&ip=8.8.8.8"


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


def test_filter_scrubs_a_record_message(caplog) -> None:
    logger = logging.getLogger("test_leak")
    logger.addFilter(RedactSecretsFilter())

    with caplog.at_level(logging.INFO, logger="test_leak"):
        logger.info("HTTP Request: GET %s", SHODAN_URL)

    assert "abc123SECRET" not in caplog.text


def test_configure_logging_quietens_httpx_request_logging() -> None:
    """The actual leak: httpx logs full request URLs at INFO."""
    configure_logging()

    assert logging.getLogger("httpx").level >= logging.WARNING


def test_configure_logging_is_idempotent() -> None:
    configure_logging()
    configure_logging()

    root = logging.getLogger()
    assert sum(isinstance(f, RedactSecretsFilter) for f in root.filters) == 1
