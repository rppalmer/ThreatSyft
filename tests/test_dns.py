import time

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
    monkeypatch.setattr(dns_resolver, "Resolver", FakeResolver)

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


def test_dns_budget_is_shared_across_record_types_not_per_record(monkeypatch) -> None:
    """lifetime is per resolve() call, and this resolves five record types.

    Setting it to the full timeout each time makes the worst case five times the
    configured value, long enough for a host to cancel the call outright.
    """
    monkeypatch.setenv("THREATSYFT_TIMEOUT_SECONDS", "10")
    lifetimes = []

    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, domain, record_type):
            lifetimes.append(self.lifetime)
            raise dns_resolver.NoAnswer()

    monkeypatch.setattr(dns_resolver, "Resolver", FakeResolver)

    dns_module.dns_lookup("example.com")

    assert lifetimes, "resolver was never called"
    assert max(lifetimes) <= 10.0
    assert lifetimes == sorted(lifetimes, reverse=True), "budget must shrink as it is spent"
    assert sum(1 for value in lifetimes if value == 10.0) <= 1


def test_dns_stops_once_the_budget_is_spent(monkeypatch) -> None:
    monkeypatch.setenv("THREATSYFT_TIMEOUT_SECONDS", "0.05")
    calls = []

    class SlowResolver:
        timeout = None
        lifetime = None

        def resolve(self, domain, record_type):
            calls.append(record_type)
            time.sleep(0.06)
            raise dns_resolver.NoAnswer()

    monkeypatch.setattr(dns_resolver, "Resolver", SlowResolver)

    result = dns_module.dns_lookup("example.com")

    assert result["ok"] is False
    assert result["error"]["code"] == "timeout"
    assert len(calls) < len(dns_module.RECORD_TYPES), "should not attempt every record type"
