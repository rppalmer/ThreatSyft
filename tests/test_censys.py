import httpx

from threatsyft.enrichment import censys

RESOURCE = {
    "ip": "45.83.192.4",
    "location": {
        "continent": "Europe",
        "country": "Germany",
        "country_code": "DE",
        "province": "Hesse",
        "city": "Frankfurt",
        "postal_code": "60313",
        "coordinates": {"latitude": 50.1, "longitude": 8.6},
    },
    "autonomous_system": {
        "asn": 205100,
        "name": "F3NETZE",
        "description": "F3 Netze",
        "bgp_prefix": "45.83.192.0/22",
        "country_code": "DE",
    },
    "service_count": 22,
    "services": [
        {
            "port": 22,
            "protocol": "SSH",
            "transport_protocol": "tcp",
            "software": [{"vendor": "openbsd", "product": "openssh"}],
            "banner": "SSH-2.0-OpenSSH_8.4",
            "ssh": {"lots": "of detail"},
        }
    ],
    "dns": {
        "names": ["a.example", "b.example"],
        # A reverse index of unrelated domains, not properties of this host.
        "forward_dns": {"unrelated.example": {"record_type": "A"}},
    },
    "whois": {"large": "object"},
}


def _respond(status: int, payload: dict | None = None):
    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        return httpx.Response(status, request=httpx.Request("GET", url), json=payload or {})

    return fake_get


def test_censys_host_lookup_missing_api_key(monkeypatch) -> None:
    monkeypatch.delenv("CENSYS_API_KEY", raising=False)

    result = censys.censys_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "missing_api_key"


def test_censys_host_lookup_rejects_invalid_ip() -> None:
    result = censys.censys_host_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"


def test_censys_host_lookup_success(monkeypatch) -> None:
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-key")

    def fake_get(url: str, headers: dict[str, str], timeout: float) -> httpx.Response:
        assert url == ("https://api.platform.censys.io/v3/global/asset/host/45.83.192.4")
        assert headers["Authorization"] == "Bearer censys-test-key"
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"result": {"resource": RESOURCE}},
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    data = censys.censys_host_lookup("45.83.192.4")["data"]

    assert data["autonomous_system"]["asn"] == 205100
    assert data["location"]["city"] == "Frankfurt"
    assert data["service_count"] == 22
    assert data["services"] == [
        {
            "port": 22,
            "protocol": "SSH",
            "transport_protocol": "tcp",
            "software": [{"vendor": "openbsd", "product": "openssh"}],
        }
    ]
    assert data["dns_names"] == ["a.example", "b.example"]
    assert data["source"] == "censys"


def test_censys_omits_per_protocol_bulk_and_reverse_dns(monkeypatch) -> None:
    """Banners, TLS detail and forward_dns are the bulk and answer no question.

    forward_dns is a reverse index of unrelated domains pointing at the address,
    not a property of the host, and runs to hundreds of entries on a busy IP.
    """
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-key")
    monkeypatch.setattr(httpx, "get", _respond(200, {"result": {"resource": RESOURCE}}))

    data = censys.censys_host_lookup("45.83.192.4")["data"]

    assert "forward_dns" not in data
    assert "whois" not in data
    assert set(data["services"][0]) == {
        "port",
        "protocol",
        "transport_protocol",
        "software",
    }


def test_censys_reports_totals_beside_the_truncated_lists(monkeypatch) -> None:
    """A caller must be able to see that it is looking at a slice."""
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-key")
    resource = dict(RESOURCE)
    resource["services"] = [dict(RESOURCE["services"][0]) for _ in range(40)]
    resource["dns"] = {"names": [f"host{index}.example" for index in range(60)]}
    monkeypatch.setattr(httpx, "get", _respond(200, {"result": {"resource": resource}}))

    data = censys.censys_host_lookup("45.83.192.4")["data"]

    assert len(data["services"]) == censys.MAX_SERVICES
    assert data["service_count"] == 22
    assert len(data["dns_names"]) == censys.MAX_DNS_NAMES
    assert data["dns_name_count"] == 60


def test_censys_host_lookup_reports_an_unknown_host(monkeypatch) -> None:
    monkeypatch.setenv("CENSYS_API_KEY", "censys-test-key")
    monkeypatch.setattr(httpx, "get", _respond(404))

    result = censys.censys_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_censys_host_lookup_reports_an_unauthorized_key(monkeypatch) -> None:
    monkeypatch.setenv("CENSYS_API_KEY", "bad")
    monkeypatch.setattr(httpx, "get", _respond(401))

    result = censys.censys_host_lookup("8.8.8.8")

    assert result["ok"] is False
    assert result["error"]["code"] == "authentication_error"
