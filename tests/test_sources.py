import asyncio

import httpx
import pytest

from osint_mcp import sources


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("https://www.example.com/login?x=1", "www.example.com"),
        ("example.com:8443/path", "example.com"),
    ],
)
def test_clean_domain(raw, expected):
    assert sources.clean_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "https://"])
def test_clean_domain_rejects_garbage(raw):
    with pytest.raises(ValueError):
        sources.clean_domain(raw)


def test_clean_ip():
    assert sources.clean_ip(" 8.8.8.8 ") == "8.8.8.8"
    assert sources.clean_ip("2001:4860:4860:0:0:0:0:8888") == "2001:4860:4860::8888"
    with pytest.raises(ValueError):
        sources.clean_ip("999.1.1.1")


def _vcard(name=None, email=None):
    fields = [["version", {}, "text", "4.0"]]
    if name:
        fields.append(["fn", {}, "text", name])
    if email:
        fields.append(["email", {}, "text", email])
    return ["vcard", fields]


RDAP_DOMAIN = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:39Z"},
    ],
    "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "A.IANA-SERVERS.NET"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": _vcard("RESERVED-Internet Assigned Numbers Authority"),
            "entities": [{"roles": ["abuse"], "vcardArray": _vcard(email="abuse@iana.org")}],
        }
    ],
}


def test_parse_rdap_domain():
    info = sources.parse_rdap_domain(RDAP_DOMAIN)
    assert info["domain"] == "example.com"
    assert info["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert info["abuse_email"] == "abuse@iana.org"
    assert info["registered"] == "1995-08-14T04:00:00Z"
    assert info["expires"] == "2026-08-13T04:00:00Z"
    assert info["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]


def test_parse_rdap_domain_handles_missing_bits():
    info = sources.parse_rdap_domain({"ldhName": "foo.ro"})
    assert info["registrar"] is None
    assert info["nameservers"] == []


def test_parse_rdap_ip():
    data = {
        "name": "GOGL",
        "handle": "NET-8-8-8-0-2",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
        "entities": [
            {"roles": ["registrant"], "vcardArray": _vcard("Google LLC")},
            {"roles": ["abuse"], "vcardArray": _vcard("Abuse", "network-abuse@google.com")},
        ],
    }
    info = sources.parse_rdap_ip(data)
    assert info["network"] == "GOGL"
    assert info["cidrs"] == ["8.8.8.0/24"]
    assert info["org"] == "Google LLC"
    assert info["abuse_email"] == "network-abuse@google.com"


def test_parse_crtsh_dedupes_and_filters():
    rows = [
        {"name_value": "example.com\nwww.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "API.example.com\nmail.example.com"},
        {"name_value": "www.example.com"},
        {"name_value": "notexample.com\nexample.com.evil.net"},
    ]
    assert sources.parse_crtsh(rows, "example.com") == [
        "api.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]


def test_parse_cdx():
    rows = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200101000000", "http://example.com/", "200", "text/html"],
    ]
    snaps = sources.parse_cdx(rows)
    assert snaps[0]["statuscode"] == "200"
    assert snaps[0]["archive_url"] == "https://web.archive.org/web/20200101000000/http://example.com/"
    assert sources.parse_cdx([]) == []


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_crtsh_subdomains_request():
    seen = {}

    def handler(request):
        seen["q"] = request.url.params["q"]
        return httpx.Response(200, json=[{"name_value": "a.example.com"}])

    async def go():
        async with _client(handler) as c:
            return await sources.crtsh_subdomains(c, "example.com")

    result = asyncio.run(go())
    assert seen["q"] == "%.example.com"
    assert result["subdomains"] == ["a.example.com"]
    assert result["certs_seen"] == 1


def test_wayback_newest_first():
    def handler(request):
        assert request.url.params["limit"] == "-2"
        return httpx.Response(200, json=[
            ["timestamp", "original", "statuscode", "mimetype"],
            ["20190101000000", "http://example.com/", "200", "text/html"],
            ["20240101000000", "http://example.com/", "200", "text/html"],
        ])

    async def go():
        async with _client(handler) as c:
            return await sources.wayback_snapshots(c, "example.com", limit=2)

    result = asyncio.run(go())
    assert [s["timestamp"] for s in result["snapshots"]] == ["20240101000000", "20190101000000"]


def test_internetdb_404_is_not_an_error():
    async def go():
        async with _client(lambda r: httpx.Response(404, json={"detail": "No information available"})) as c:
            return await sources.internetdb(c, "10.0.0.1")

    assert asyncio.run(go())["ports"] == []


def test_http_headers_reports_missing():
    def handler(request):
        return httpx.Response(200, headers={"Server": "nginx", "X-Frame-Options": "DENY"})

    async def go():
        async with _client(handler) as c:
            return await sources.http_headers(c, "example.com")

    result = asyncio.run(go())
    assert result["url"] == "https://example.com"
    assert result["server"] == "nginx"
    assert "x-frame-options" not in result["missing_security_headers"]
    assert "strict-transport-security" in result["missing_security_headers"]


def test_flaky_endpoints_get_retried(monkeypatch):
    async def no_sleep(_):
        pass

    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)
    responses = iter([httpx.Response(503), httpx.Response(502), httpx.Response(200, json=[])])

    async def go():
        async with _client(lambda r: next(responses)) as c:
            return await sources.crtsh_subdomains(c, "example.com")

    assert asyncio.run(go())["subdomains"] == []


def test_gives_up_after_retries(monkeypatch):
    async def no_sleep(_):
        pass

    monkeypatch.setattr(sources.asyncio, "sleep", no_sleep)

    async def go():
        async with _client(lambda r: httpx.Response(503)) as c:
            return await sources.wayback_snapshots(c, "example.com")

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(go())


def test_rdap_domain_404_explains_itself():
    async def go():
        async with _client(lambda r: httpx.Response(404)) as c:
            return await sources.rdap_domain(c, "emag.ro")

    result = asyncio.run(go())
    assert "no RDAP data" in result["error"]
