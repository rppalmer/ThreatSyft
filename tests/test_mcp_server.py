import anyio

from threatsyft.mcp.enrichment_server import mcp


def test_mcp_server_registers_expected_tools() -> None:
    tools = anyio.run(mcp.list_tools)

    assert [tool.name for tool in tools] == [
        "enrichment_status",
        "dns_lookup",
        "rdap_lookup",
        "whois_lookup",
        "abuseipdb_check_ip",
        "greynoise_ip_context",
        "virustotal_ip_report",
        "virustotal_domain_report",
        "virustotal_url_report",
        "virustotal_file_report",
        "securitytrails_domain_lookup",
        "shodan_host_lookup",
        "ipgeolocation_lookup",
        "alienvault_indicator_lookup",
        "google_safebrowsing_check_url",
        "enrich",
    ]
