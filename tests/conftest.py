import ipaddress

import pytest

from threatsyft.research import url_validation


@pytest.fixture(autouse=True)
def stub_dns_resolution(monkeypatch):
    """Keep research URL validation hermetic.

    ``normalize_public_http_url`` resolves hostnames to guard against SSRF. Unit
    tests must not depend on real DNS, so by default resolution returns a single
    public address. Tests exercising the SSRF guard override this to return a
    private/reserved address.
    """
    monkeypatch.setattr(
        url_validation,
        "resolve_host_addresses",
        lambda hostname: [ipaddress.ip_address("93.184.216.34")],
    )
