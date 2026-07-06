import dns.exception as dns_exception
import dns.resolver as dns_resolver

from threatsyft.enrichment import dns as dns_module


class FakeAnswer:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class FakeResolver:
    timeout = 0
    lifetime = 0

    def resolve(self, domain: str, record_type: str) -> list[object]:
        assert domain == "example.com"
        if record_type == "A":
            return [FakeAnswer("93.184.216.34")]
        if record_type == "MX":
            return [FakeAnswer("10 mail.example.com.")]
        raise dns_resolver.NoAnswer()


def test_dns_lookup_success(monkeypatch) -> None:
    monkeypatch.setattr(dns_module.dns.resolver, "Resolver", FakeResolver)

    result = dns_module.dns_lookup("example.com")

    assert result["ok"] is True
    assert result["data"]["records"]["A"] == ["93.184.216.34"]
    assert result["data"]["records"]["MX"] == ["10 mail.example.com"]
    assert result["data"]["records"]["AAAA"] == []


def test_dns_lookup_nxdomain(monkeypatch) -> None:
    class NXDomainResolver(FakeResolver):
        def resolve(self, domain: str, record_type: str) -> list[object]:
            raise dns_resolver.NXDOMAIN()

    monkeypatch.setattr(dns_module.dns.resolver, "Resolver", NXDomainResolver)

    result = dns_module.dns_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "not_found"


def test_dns_lookup_timeout(monkeypatch) -> None:
    class TimeoutResolver(FakeResolver):
        def resolve(self, domain: str, record_type: str) -> list[object]:
            raise dns_exception.Timeout()

    monkeypatch.setattr(dns_module.dns.resolver, "Resolver", TimeoutResolver)

    result = dns_module.dns_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"


def test_dns_lookup_invalid_input() -> None:
    result = dns_module.dns_lookup("https://example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "invalid_input"
