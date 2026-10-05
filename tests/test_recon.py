import asyncio

import httpx
import pytest

from osint_mcp import recon


@pytest.fixture
def fake_sources(monkeypatch):
    async def rdap_domain(client, domain):
        return {"domain": domain, "registrar": "Example Registrar", "expires": "2099-01-01T00:00:00Z"}

    async def dns_records(domain, types=None, nameserver=None):
        return {"domain": domain, "records": {"A": ["93.184.215.14", "<timeout>"], "MX": ["0 ."]}}

    async def email_check(client, domain, dkim_selectors=None):
        return {"grade": "C", "issues": ["DMARC is p=none, that's monitoring only"]}

    async def fetch_certificate(host, port=443, timeout=10.0):
        return {"host": host, "valid": True, "days_left": 5, "warnings": ["certificate expires in 5 days"]}

    async def http_headers(client, url):
        return {"status": 200, "headers": {"server": "x"}, "missing_security_headers": ["content-security-policy"]}

    async def crtsh(client, domain):
        return {"domain": domain, "certs_seen": 300, "subdomains": [f"s{i}.{domain}" for i in range(150)]}

    async def asn_info(client, query, include_prefixes=True):
        return {"asn": 15133, "holder": "EDGECAST"}

    async def reverse_dns(ip):
        return []

    async def internetdb(client, ip):
        return {"ip": ip, "ports": [80, 443], "vulns": ["CVE-2023-0001"]}

    s = recon.sources
    monkeypatch.setattr(s, "rdap_domain", rdap_domain)
    monkeypatch.setattr(s, "dns_records", dns_records)
    monkeypatch.setattr(s, "http_headers", http_headers)
    monkeypatch.setattr(s, "crtsh_subdomains", crtsh)
    monkeypatch.setattr(s, "asn_info", asn_info)
    monkeypatch.setattr(s, "reverse_dns", reverse_dns)
    monkeypatch.setattr(s, "internetdb", internetdb)
    monkeypatch.setattr(recon.mailsec, "check", email_check)
    monkeypatch.setattr(recon.tlscert, "fetch_certificate", fetch_certificate)
    return monkeypatch


def run(include_subdomains=True):
    return asyncio.run(recon.recon(None, "example.com", include_subdomains))


def test_report_shape(fake_sources):
    report = run()
    assert report["domain"] == "example.com"
    assert set(report) >= {"whois", "dns", "email", "tls", "http", "subdomains", "ips", "highlights"}
    # only real ips get looked up, not the "<timeout>" placeholder
    assert list(report["ips"]) == ["93.184.215.14"]
    assert "headers" not in report["http"]
    assert report["subdomains"]["count"] == 150
    assert len(report["subdomains"]["names"]) == recon.MAX_SUBDOMAINS


def test_highlights(fake_sources):
    h = run()["highlights"]
    assert "email security grade C (DMARC is p=none, that's monitoring only)" in h
    assert "TLS: certificate expires in 5 days" in h
    assert "website is missing 1 security headers: content-security-policy" in h
    assert "150 subdomains seen in certificate transparency logs" in h
    assert "93.184.215.14 (AS15133 EDGECAST): open ports 80, 443" in h
    assert any("1 known CVEs" in x for x in h)


def test_one_failing_check_doesnt_kill_the_report(fake_sources):
    async def broken(client, domain):
        req = httpx.Request("GET", "https://crt.sh/")
        raise httpx.HTTPStatusError("boom", request=req, response=httpx.Response(503, request=req))

    fake_sources.setattr(recon.sources, "crtsh_subdomains", broken)
    report = run()
    assert report["subdomains"] == {"error": "crt.sh returned 503"}
    assert report["email"]["grade"] == "C"


def test_skip_subdomains(fake_sources):
    assert "subdomains" not in run(include_subdomains=False)


def test_expiring_domain_is_highlighted():
    h = recon.highlights({"whois": {"expires": "2000-01-01T00:00:00Z"}})
    assert h[0].startswith("domain registration expires in -")


def test_no_direct_web_mode_skips_tls_http_and_policy(fake_sources):
    async def email(client, domain, dkim_selectors=None, fetch_policy=True):
        assert not fetch_policy
        return {'grade': 'C', 'issues': []}

    async def forbidden(*args, **kwargs):
        raise AssertionError('direct connection was attempted')

    fake_sources.setattr(recon.mailsec, 'check', email)
    fake_sources.setattr(recon.sources, 'http_headers', forbidden)
    fake_sources.setattr(recon.tlscert, 'fetch_certificate', forbidden)
    report = asyncio.run(recon.recon(None, 'example.com', False, False))
    assert report['coverage']['http'] == report['coverage']['tls'] == 'skipped'
    assert 'http' not in report and 'tls' not in report
    assert report['coverage']['dns'] == 'partial'
