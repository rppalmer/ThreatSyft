import httpx

from threatsyft.enrichment import virustotal


def test_virustotal_ip_report_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_virustotal_ip_report_rejects_invalid_ip() -> None:
    result = virustotal.virustotal_ip_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_virustotal_ip_report_success(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
        assert headers["x-apikey"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "id": "8.8.8.8",
                    "type": "ip_address",
                    "attributes": {
                        "asn": 15169,
                        "as_owner": "GOOGLE",
                        "country": "US",
                        "continent": "NA",
                        "network": "8.8.8.0/24",
                        "regional_internet_registry": "ARIN",
                        "reputation": 10,
                        "last_analysis_stats": {
                            "harmless": 82,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 12,
                            "timeout": 0,
                        },
                        "total_votes": {"harmless": 2, "malicious": 0},
                        "tags": ["dns"],
                        "last_analysis_date": 1715609875,
                        "last_modification_date": 1715609900,
                    },
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["asn"] == 15169
    assert result["data"]["last_analysis_stats"]["harmless"] == 82
    assert "verdict" not in result["data"]
    assert result["data"]["last_analysis_date"] == "2024-05-13T14:17:55+00:00"


def test_virustotal_ip_report_passes_analysis_stats_through_unjudged(monkeypatch) -> None:
    """One flagging engine out of 43 is a number, not a conclusion.

    The engine counts and VirusTotal's own reputation come back untouched so the
    caller can weigh them; collapsing them to "malicious" here would hide how
    thin the evidence is.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "reputation": -5,
                        "last_analysis_stats": {
                            "harmless": 40,
                            "malicious": 2,
                            "suspicious": 1,
                        },
                    }
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is True
    assert result["data"]["last_analysis_stats"] == {
        "harmless": 40,
        "malicious": 2,
        "suspicious": 1,
    }
    assert result["data"]["reputation"] == -5
    assert "verdict" not in result["data"]


def test_virustotal_ip_report_not_found(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_virustotal_ip_report_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_virustotal_ip_report_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_virustotal_ip_report_timeout(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_virustotal_ip_report_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_ip_report_missing_attributes(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"id": "8.8.8.8"}},
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_ip_report("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_domain_report_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_virustotal_domain_report_rejects_url() -> None:
    result = virustotal.virustotal_domain_report("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_virustotal_domain_report_success(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://www.virustotal.com/api/v3/domains/example.com"
        assert headers["x-apikey"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "id": "example.com",
                    "type": "domain",
                    "attributes": {
                        "reputation": 25,
                        "registrar": "RESERVED-Internet Assigned Numbers Authority",
                        "whois_date": 1715609875,
                        "creation_date": 808372800,
                        "last_analysis_stats": {
                            "harmless": 80,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 10,
                        },
                        "last_dns_records": [
                            {"type": "A", "value": "93.184.216.34", "ttl": 300},
                            {"type": "TXT", "value": "v=spf1 -all", "ttl": 300},
                        ],
                        "categories": {"Forcepoint ThreatSeeker": "information technology"},
                        "total_votes": {"harmless": 5, "malicious": 0},
                        "tags": ["test-domain"],
                        "last_analysis_date": 1715609900,
                        "last_modification_date": 1715610000,
                    },
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("Example.COM.")

    assert result["ok"] is True
    assert result["data"]["domain"] == "example.com"
    assert result["data"]["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert result["data"]["last_dns_records"][0] == {
        "type": "A",
        "value": "93.184.216.34",
        "ttl": 300,
    }
    assert "verdict" not in result["data"]
    assert result["data"]["source_url"] == "https://www.virustotal.com/gui/domain/example.com"


def test_virustotal_domain_report_passes_analysis_stats_through_unjudged(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "reputation": -1,
                        "last_analysis_stats": {
                            "harmless": 20,
                            "malicious": 0,
                            "suspicious": 2,
                        },
                    }
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is True
    assert result["data"]["last_analysis_stats"]["suspicious"] == 2
    assert result["data"]["reputation"] == -1
    assert "verdict" not in result["data"]


def test_virustotal_domain_report_not_found(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_virustotal_domain_report_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_virustotal_domain_report_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_virustotal_domain_report_timeout(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_virustotal_domain_report_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_domain_report_missing_attributes(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"id": "example.com"}},
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_domain_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_url_report_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_virustotal_url_report_rejects_domain_only() -> None:
    result = virustotal.virustotal_url_report("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_virustotal_url_report_success(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8"
        assert headers["x-apikey"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8",
                    "type": "url",
                    "attributes": {
                        "last_final_url": "https://example.com/",
                        "title": "Example Domain",
                        "reputation": 5,
                        "last_analysis_stats": {
                            "harmless": 80,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 10,
                        },
                        "categories": {"Forcepoint ThreatSeeker": "information technology"},
                        "total_votes": {"harmless": 1, "malicious": 0},
                        "tags": ["example"],
                        "first_submission_date": 1715609800,
                        "last_submission_date": 1715609875,
                        "last_analysis_date": 1715609900,
                        "last_modification_date": 1715610000,
                        "last_http_response_code": 200,
                    },
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is True
    assert result["data"]["url"] == "https://example.com/"
    assert result["data"]["id"] == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"
    assert result["data"]["final_url"] == "https://example.com/"
    assert result["data"]["title"] == "Example Domain"
    assert "verdict" not in result["data"]
    assert result["data"]["source_url"] == (
        "https://www.virustotal.com/gui/url/aHR0cHM6Ly9leGFtcGxlLmNvbS8"
    )


def test_virustotal_url_report_passes_analysis_stats_through_unjudged(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "reputation": -10,
                        "last_analysis_stats": {
                            "harmless": 20,
                            "malicious": 3,
                            "suspicious": 1,
                        },
                    }
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://bad.example/")

    assert result["ok"] is True
    assert result["data"]["last_analysis_stats"]["malicious"] == 3
    assert result["data"]["reputation"] == -10
    assert "verdict" not in result["data"]


def test_virustotal_url_report_not_found(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_virustotal_url_report_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_virustotal_url_report_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_virustotal_url_report_timeout(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_virustotal_url_report_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_url_report_missing_attributes(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"id": "aHR0cHM6Ly9leGFtcGxlLmNvbS8"}},
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_url_report("https://example.com/")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_file_report_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = virustotal.virustotal_file_report("d41d8cd98f00b204e9800998ecf8427e")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_virustotal_file_report_rejects_invalid_hash() -> None:
    result = virustotal.virustotal_file_report("not-a-hash")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_virustotal_file_report_success(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == "https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e"
        assert headers["x-apikey"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "id": "d41d8cd98f00b204e9800998ecf8427e",
                    "type": "file",
                    "attributes": {
                        "md5": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb924"
                        "27ae41e4649b934ca495991b7852b855",
                        "meaningful_name": "empty",
                        "names": ["empty", "zero-byte"],
                        "type_description": "unknown",
                        "type_tag": "unknown",
                        "size": 0,
                        "reputation": 0,
                        "last_analysis_stats": {
                            "harmless": 60,
                            "malicious": 0,
                            "suspicious": 0,
                        },
                        "total_votes": {"harmless": 1, "malicious": 0},
                        "tags": ["empty"],
                        "signature_info": {"description": "unsigned"},
                        "first_submission_date": 1715609800,
                        "last_submission_date": 1715609875,
                        "last_analysis_date": 1715609900,
                        "last_modification_date": 1715610000,
                    },
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("D41D8CD98F00B204E9800998ECF8427E")

    assert result["ok"] is True
    assert result["data"]["hash"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert result["data"]["hash_type"] == "md5"
    assert result["data"]["meaningful_name"] == "empty"
    assert result["data"]["sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert "verdict" not in result["data"]


def test_virustotal_file_report_passes_analysis_stats_through_unjudged(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "reputation": -25,
                        "last_analysis_stats": {
                            "harmless": 10,
                            "malicious": 20,
                            "suspicious": 2,
                        },
                    }
                }
            },
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is True
    assert result["data"]["last_analysis_stats"]["malicious"] == 20
    assert result["data"]["reputation"] == -25
    assert "verdict" not in result["data"]


def test_virustotal_file_report_not_found(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_virustotal_file_report_authentication_error(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "bad-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(401, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_virustotal_file_report_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_virustotal_file_report_timeout(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_virustotal_file_report_malformed_response(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_virustotal_file_report_missing_attributes(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"id": "a" * 64}},
        )

    monkeypatch.setattr(virustotal.httpx, "get", fake_get)

    result = virustotal.virustotal_file_report("A" * 64)

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
