from threatsyft.enrichment import whois as whois_module


def test_domain_whois_success(monkeypatch) -> None:
    def fake_whois(domain: str, timeout: float | None = None) -> dict[str, object]:
        assert domain == "example.com"
        assert timeout, "the configured timeout must reach python-whois"
        return {
            "domain_name": "EXAMPLE.COM",
            "registrar": "Example Registrar",
            "whois_server": "whois.example.test",
            "creation_date": "1995-08-14",
            "expiration_date": "2026-08-13",
            "updated_date": "2025-01-01",
            "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "status": ["active"],
            "emails": "admin@example.com",
            "text": "raw whois text",
        }

    monkeypatch.setattr(whois_module.whois, "whois", fake_whois)

    result = whois_module.whois_lookup("example.com")

    assert result["ok"] is True
    assert result["data"]["registrar"] == "Example Registrar"
    assert result["data"]["raw"] == "raw whois text"


def test_ip_whois_success(monkeypatch) -> None:
    class FakeIPWhois:
        def __init__(self, ip: str, timeout: float, proxy_opener: object) -> None:
            assert ip == "8.8.8.8"
            assert timeout > 0
            assert proxy_opener is not None

        def lookup_rdap(self) -> dict[str, object]:
            return {
                "asn": "15169",
                "asn_description": "GOOGLE",
                "asn_country_code": "US",
                "network": {
                    "name": "GOGL",
                    "handle": "NET-8-8-8-0-1",
                    "country": "US",
                    "start_address": "8.8.8.0",
                    "end_address": "8.8.8.255",
                },
            }

    monkeypatch.setattr(whois_module, "IPWhois", FakeIPWhois)

    result = whois_module.whois_lookup("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["asn"] == "15169"
    assert result["data"]["network"]["country"] == "US"


def test_whois_lookup_failure(monkeypatch) -> None:
    def fake_whois(domain: str, timeout: float | None = None) -> dict[str, object]:
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(whois_module.whois, "whois", fake_whois)

    result = whois_module.whois_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "upstream_error"


def test_domain_whois_passes_the_configured_timeout(monkeypatch) -> None:
    """Without it python-whois uses its own default and accumulates it per referral hop."""
    monkeypatch.setenv("THREATSYFT_TIMEOUT_SECONDS", "7")
    seen = {}

    def fake_whois(domain: str, timeout: float | None = None):
        seen["timeout"] = timeout
        return {"domain_name": "example.com"}

    monkeypatch.setattr(whois_module.whois, "whois", fake_whois)

    whois_module.whois_lookup("example.com")

    assert seen["timeout"] == 7.0
