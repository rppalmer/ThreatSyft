import httpx

from threatsyft.knowledge import cve


def test_cve_lookup_rejects_invalid_cve() -> None:
    result = cve.cve_lookup("2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_cve_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        assert url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        assert params == {"cveId": "CVE-2024-3400"}
        assert headers["apiKey"] == "test-key"
        assert timeout > 0
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-3400",
                            "sourceIdentifier": "psirt@example.com",
                            "published": "2024-04-12T08:15:06.230",
                            "lastModified": "2025-11-04T16:49:20.907",
                            "vulnStatus": "Analyzed",
                            "descriptions": [{"lang": "en", "value": "Command injection."}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "source": "nvd@nist.gov",
                                        "type": "Primary",
                                        "cvssData": {
                                            "version": "3.1",
                                            "vectorString": "CVSS:3.1/AV:N/AC:L",
                                            "baseScore": 10.0,
                                            "baseSeverity": "CRITICAL",
                                        },
                                        "exploitabilityScore": 3.9,
                                        "impactScore": 6.0,
                                    }
                                ]
                            },
                            "weaknesses": [
                                {
                                    "description": [
                                        {"lang": "en", "value": "CWE-77"},
                                        {"lang": "en", "value": "CWE-20"},
                                    ]
                                }
                            ],
                            "references": [
                                {
                                    "url": "https://example.com/advisory",
                                    "source": "Vendor",
                                    "tags": ["Vendor Advisory"],
                                }
                            ],
                            "cisaExploitAdd": "2024-04-12",
                            "cisaActionDue": "2024-04-19",
                            "cisaRequiredAction": "Apply mitigations.",
                            "cisaVulnerabilityName": "PAN-OS Command Injection",
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": (
                                                        "cpe:2.3:o:paloaltonetworks:pan-os:"
                                                        "*:*:*:*:*:*:*:*"
                                                    ),
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("cve-2024-3400")

    assert result["ok"] is True
    assert result["data"]["cve_id"] == "CVE-2024-3400"
    assert result["data"]["description"] == "Command injection."
    assert result["data"]["cvss"]["base_severity"] == "CRITICAL"
    assert result["data"]["weaknesses"] == ["CWE-20", "CWE-77"]
    assert result["data"]["cisa"]["exploit_add"] == "2024-04-12"
    assert result["data"]["affected_cpes"] == ["cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"]


def test_cve_lookup_not_found(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"vulnerabilities": []},
        )

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-1999-0001")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_cve_lookup_authentication_error(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(403, request=httpx.Request("GET", url))

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"


def test_cve_lookup_rate_limited(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(429, request=httpx.Request("GET", url))

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "rate_limited"


def test_cve_lookup_timeout(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_cve_lookup_malformed_json(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), content=b"not-json")

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"


def test_cve_lookup_unexpected_shape(monkeypatch) -> None:
    def fake_get(
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        timeout: float,
    ) -> httpx.Response:
        return httpx.Response(200, request=httpx.Request("GET", url), json={"format": "NVD_CVE"})

    monkeypatch.setattr(cve.httpx, "get", fake_get)

    result = cve.cve_lookup("CVE-2024-3400")

    assert result["ok"] is False
    assert result["error"]["code"] == "parse_error"
