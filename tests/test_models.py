from investigatinator.enrichment.models import (
    InputValidationError,
    classify_target,
    error_response,
    normalize_domain,
    normalize_ip,
    normalize_url,
    success_response,
)


def test_success_response_has_common_envelope() -> None:
    result = success_response("dns_lookup", {"domain": "example.com"}, {"records": {}})

    assert result["ok"] is True
    assert result["tool"] == "dns_lookup"
    assert result["query"] == {"domain": "example.com"}
    assert result["data"] == {"records": {}}
    assert result["error"] is None


def test_error_response_has_common_envelope() -> None:
    result = error_response("dns_lookup", {"domain": ""}, "invalid_input", "Domain is required.")

    assert result["ok"] is False
    assert result["tool"] == "dns_lookup"
    assert result["data"] is None
    assert result["error"]["code"] == "invalid_input"


def test_normalize_domain_accepts_plain_domain() -> None:
    assert normalize_domain("Example.COM.") == "example.com"


def test_normalize_domain_rejects_url() -> None:
    try:
        normalize_domain("https://example.com")
    except InputValidationError as exc:
        assert "not a URL" in str(exc)
    else:
        raise AssertionError("Expected InputValidationError")


def test_classify_target_detects_ip_and_domain() -> None:
    assert classify_target("8.8.8.8") == ("ip", "8.8.8.8")
    assert classify_target("Example.com") == ("domain", "example.com")


def test_normalize_ip_rejects_domain() -> None:
    try:
        normalize_ip("example.com")
    except InputValidationError as exc:
        assert "valid IP" in str(exc)
    else:
        raise AssertionError("Expected InputValidationError")


def test_normalize_url_accepts_http_url() -> None:
    assert normalize_url("https://example.com/path") == "https://example.com/path"


def test_normalize_url_rejects_domain_only() -> None:
    try:
        normalize_url("example.com")
    except InputValidationError as exc:
        assert "http://" in str(exc)
    else:
        raise AssertionError("Expected InputValidationError")
