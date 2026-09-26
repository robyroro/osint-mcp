import asyncio

import httpx
import pytest

from osint_mcp import mailsec


def test_spf_basic():
    spf = mailsec.parse_spf(["google-site-verification=abc", "v=spf1 include:_spf.google.com mx -all"])
    assert spf["valid"]
    assert spf["all"] == "-all"
    assert spf["lookups"] == 2


def test_spf_counts_lookup_mechanisms():
    spf = mailsec.parse_spf(["v=spf1 a a:x.com mx/24 ptr exists:%{i}.x.com include:a include:b ip4:1.2.3.4 ~all"])
    assert spf["lookups"] == 7
    assert spf["all"] == "~all"


def test_spf_missing_and_duplicate():
    assert mailsec.parse_spf(["hello"]) == {"present": False}
    dup = mailsec.parse_spf(["v=spf1 -all", "v=spf1 mx -all"])
    assert dup["present"] and not dup["valid"]


def test_spf_redirect():
    spf = mailsec.parse_spf(["v=spf1 redirect=_spf.example.com"])
    assert spf["redirect"] == "_spf.example.com"
    assert spf["all"] is None


def test_dmarc():
    d = mailsec.parse_dmarc(["v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com"])
    assert d["policy"] == "reject"
    assert d["subdomain_policy"] == "quarantine"
    assert d["pct"] == 50
    assert d["rua"] == ["mailto:a@x.com", "mailto:b@x.com"]


def test_dmarc_defaults_and_garbage():
    d = mailsec.parse_dmarc(["v=DMARC1; p=none"])
    assert d["pct"] == 100 and d["subdomain_policy"] == "none" and d["rua"] == []
    assert not mailsec.parse_dmarc(["v=DMARC1; rua=mailto:x@y.z"])["valid"]
    assert mailsec.parse_dmarc([]) == {"present": False}


def test_mta_sts_policy():
    p = mailsec.parse_mta_sts_policy("version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.example.net\nmax_age: 86400\n")
    assert p == {"version": "STSv1", "mode": "enforce", "mx": ["mx1.example.com", "*.example.net"], "max_age": "86400"}


SPF_STRICT = mailsec.parse_spf(["v=spf1 mx -all"])
SPF_PLUS = mailsec.parse_spf(["v=spf1 +all"])
NO_SPF = mailsec.parse_spf([])
REJECT = mailsec.parse_dmarc(["v=DMARC1; p=reject; rua=mailto:r@x.com"])
QUARANTINE = mailsec.parse_dmarc(["v=DMARC1; p=quarantine; rua=mailto:r@x.com"])
MONITOR = mailsec.parse_dmarc(["v=DMARC1; p=none"])
NO_DMARC = mailsec.parse_dmarc([])


@pytest.mark.parametrize(
    "spf, dmarc, expected",
    [
        (SPF_STRICT, REJECT, "A"),
        (NO_SPF, REJECT, "B"),
        (SPF_STRICT, QUARANTINE, "B"),
        (SPF_STRICT, MONITOR, "C"),
        (SPF_STRICT, NO_DMARC, "D"),
        (NO_SPF, NO_DMARC, "F"),
        (SPF_PLUS, REJECT, "F"),
    ],
)
def test_grades(spf, dmarc, expected):
    letter, _ = mailsec.grade(spf, dmarc)
    assert letter == expected


def test_grade_issues_are_readable():
    _, issues = mailsec.grade(SPF_STRICT, MONITOR, {"present": False})
    assert any("p=none" in i for i in issues)
    assert any("rua" in i for i in issues)
    assert any("MTA-STS" in i for i in issues)


def test_parked_domain_hint():
    _, issues = mailsec.grade(NO_SPF, NO_DMARC, has_mx=False)
    assert any("never sends mail" in i for i in issues)
    _, issues = mailsec.grade(SPF_STRICT, REJECT, has_mx=False)
    assert not any("never sends mail" in i for i in issues)


def test_check_end_to_end(monkeypatch):
    txt = {
        "example.com": ["v=spf1 include:_spf.google.com -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        "_mta-sts.example.com": ["v=STSv1; id=2024"],
        "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjAN"],
    }

    async def fake_txt(name):
        return txt.get(name, [])

    async def fake_dns(domain, types=None, nameserver=None):
        return {"domain": domain, "records": {"MX": ["1 smtp.google.com."]}}

    monkeypatch.setattr(mailsec.sources, "txt_records", fake_txt)
    monkeypatch.setattr(mailsec.sources, "dns_records", fake_dns)

    def handler(request):
        assert request.url.host == "mta-sts.example.com"
        return httpx.Response(200, text="version: STSv1\nmode: enforce\nmx: smtp.google.com\nmax_age: 604800\n")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await mailsec.check(c, "example.com")

    result = asyncio.run(go())
    assert result["grade"] == "A"
    assert result["issues"] == []
    assert result["mta_sts"]["mode"] == "enforce"
    assert result["dkim"]["found"] == ["google"]
    assert result["dkim"]["wildcard"] is None
    assert result["tls_rpt"].startswith("v=TLSRPTv1")


def test_dkim_key():
    assert mailsec.dkim_key(["v=DKIM1; k=rsa; p=MIIB IjAN"]) == "MIIBIjAN"
    assert mailsec.dkim_key(["v=DKIM1; p="]) == ""
    assert mailsec.dkim_key(["something else"]) is None


def test_dkim_wildcard_is_not_reported_as_found(monkeypatch):
    # example.com style: *._domainkey answers everything with an empty key
    async def fake_txt(name):
        if name == "real._domainkey.example.com":
            return ["v=DKIM1; p=MIIBIjAN"]
        return ["v=DKIM1; p="]

    monkeypatch.setattr(mailsec.sources, "txt_records", fake_txt)
    dkim = asyncio.run(mailsec._dkim("example.com", ["default", "google", "real"]))
    assert dkim["found"] == ["real"]
    assert dkim["revoked"] == []
    assert "doesn't sign mail" in dkim["note"]
