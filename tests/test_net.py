import asyncio
import ssl

import httpx
import pytest

from osint_mcp import sources, tlscert

CERT = {
    "subject": ((("commonName", "github.com"),),),
    "issuer": (
        (("countryName", "GB"),),
        (("organizationName", "Sectigo Limited"),),
        (("commonName", "Sectigo ECC Domain Validation Secure Server CA"),),
    ),
    "notBefore": "Feb  5 00:00:00 2026 GMT",
    "notAfter": "Feb  5 23:59:59 2027 GMT",
    "subjectAltName": (("DNS", "github.com"), ("DNS", "www.github.com"), ("IP Address", "1.2.3.4")),
    "serialNumber": "ABC123",
}


def test_parse_cert():
    now = ssl.cert_time_to_seconds("Jan 26 00:00:00 2027 GMT")
    info = tlscert.parse_cert(CERT, now=now)
    assert info["subject"] == "github.com"
    assert info["issuer"] == "Sectigo Limited"
    assert info["sans"] == ["github.com", "www.github.com"]
    assert info["not_after"] == "2027-02-05T23:59:59Z"
    assert info["days_left"] == 10


def test_cert_warnings():
    assert tlscert.warnings_for({"days_left": 200, "tls_version": "TLSv1.3"}) == []
    assert tlscert.warnings_for({"days_left": -3, "tls_version": "TLSv1.3"}) == ["certificate is expired"]
    w = tlscert.warnings_for({"days_left": 5, "tls_version": "TLSv1.1"})
    assert "certificate expires in 5 days" in w
    assert any("deprecated" in x for x in w)


def test_unreachable_host_doesnt_raise():
    # port 9 on localhost is ~never open
    result = asyncio.run(tlscert.fetch_certificate("127.0.0.1", 9, timeout=3))
    assert "private, local and reserved" in result["error"]


@pytest.mark.parametrize(
    "raw, expected",
    [("1.1.1.1", ("ip", "1.1.1.1")), ("AS13335", ("asn", 13335)), ("as8075", ("asn", 8075)), (" 15169 ", ("asn", 15169))],
)
def test_parse_asn_query(raw, expected):
    assert sources.parse_asn_query(raw) == expected


def test_parse_asn_query_rejects_junk():
    with pytest.raises(ValueError):
        sources.parse_asn_query("cloudflare")


def _ripestat_handler(request):
    endpoint = request.url.path.split("/")[2]
    assert request.url.params["sourceapp"] == "osint-mcp"
    data = {
        "network-info": {"asns": ["13335"], "prefix": "1.1.1.0/24"},
        "as-overview": {"holder": "CLOUDFLARENET - Cloudflare, Inc.", "announced": True},
        "announced-prefixes": {"prefixes": [
            {"prefix": "2606:4700::/32"}, {"prefix": "104.16.0.0/13"}, {"prefix": "1.1.1.0/24"},
        ]},
    }[endpoint]
    return httpx.Response(200, json={"data": data})


def test_asn_info_from_ip():
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(_ripestat_handler)) as c:
            return await sources.asn_info(c, "1.1.1.1")

    info = asyncio.run(go())
    assert info["asn"] == 13335
    assert info["prefix"] == "1.1.1.0/24"
    assert info["holder"].startswith("CLOUDFLARENET")
    assert info["prefix_count"] == {"ipv4": 2, "ipv6": 1}
    assert info["prefixes"] == ["1.1.1.0/24", "104.16.0.0/13", "2606:4700::/32"]


def test_asn_info_truncates_prefixes():
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(_ripestat_handler)) as c:
            return await sources.asn_info(c, "AS13335", max_prefixes=2)

    info = asyncio.run(go())
    assert len(info["prefixes"]) == 2
    assert info["prefixes_truncated"]
