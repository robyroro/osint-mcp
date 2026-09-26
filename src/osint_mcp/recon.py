"""recon_domain: run every passive check at once and pull out what's worth a look."""

import asyncio
import ipaddress
from datetime import datetime, timezone

from . import mailsec, sources, tlscert

MAX_IPS = 3
MAX_SUBDOMAINS = 100


async def _gather(tasks):
    """Like gather() but a failing check becomes {"error": ...} instead of killing the report."""
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    out = {}
    for name, res in zip(tasks, results):
        if isinstance(res, Exception):
            out[name] = {"error": sources.describe_error(res)}
        elif isinstance(res, BaseException):
            raise res
        else:
            out[name] = res
    return out


async def _ip_details(client, ip):
    return await _gather({
        "asn": sources.asn_info(client, ip, include_prefixes=False),
        "ptr": sources.reverse_dns(ip),
        "internetdb": sources.internetdb(client, ip),
    })


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _dns_and_ips(client, domain):
    dns = await sources.dns_records(domain)
    ips = [a for a in dns.get("records", {}).get("A", []) if _is_ip(a)][:MAX_IPS]
    details = await asyncio.gather(*(_ip_details(client, ip) for ip in ips))
    return {"dns": dns, "ips": dict(zip(ips, details))}


def _days_until(iso):
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - datetime.now(timezone.utc)).days


def highlights(report):
    out = []

    whois = report.get("whois", {})
    days = _days_until(whois.get("expires"))
    if days is not None and days < 30:
        out.append(f"domain registration expires in {days} days")

    email = report.get("email", {})
    if "grade" in email:
        line = f"email security grade {email['grade']}"
        if email["issues"]:
            line += f" ({email['issues'][0]})"
        out.append(line)

    tls = report.get("tls", {})
    if tls.get("valid") is False:
        out.append(f"TLS certificate problem: {tls['error']}")
    out.extend(f"TLS: {w}" for w in tls.get("warnings", []))

    http = report.get("http", {})
    missing = http.get("missing_security_headers") or []
    if missing:
        out.append(f"website is missing {len(missing)} security headers: {', '.join(missing)}")

    subs = report.get("subdomains", {})
    if "count" in subs:
        out.append(f"{subs['count']} subdomains seen in certificate transparency logs")

    for ip, info in report.get("ips", {}).items():
        asn = info.get("asn", {})
        idb = info.get("internetdb", {})
        where = f"{ip} (AS{asn['asn']} {asn.get('holder') or ''})".replace(" )", ")") if "asn" in asn else ip
        if idb.get("ports"):
            out.append(f"{where}: open ports {', '.join(map(str, idb['ports']))}")
        if idb.get("vulns"):
            out.append(f"{where}: Shodan lists {len(idb['vulns'])} known CVEs, worth checking patch levels")

    return out


async def recon(client, domain, include_subdomains=True):
    checks = {
        "whois": sources.rdap_domain(client, domain),
        "dns_ips": _dns_and_ips(client, domain),
        "email": mailsec.check(client, domain),
        "tls": tlscert.fetch_certificate(domain),
        "http": sources.http_headers(client, domain),
    }
    if include_subdomains:
        checks["subdomains"] = sources.crtsh_subdomains(client, domain)

    results = await _gather(checks)

    dns_ips = results.pop("dns_ips")
    report = {"domain": domain, **results}
    report["dns"] = dns_ips.get("dns", dns_ips)
    report["ips"] = dns_ips.get("ips", {})

    # the full header dump and subdomain list make the report huge, trim them
    if "headers" in report["http"]:
        report["http"] = {k: v for k, v in report["http"].items() if k != "headers"}
    subs = report.get("subdomains")
    if subs and "subdomains" in subs:
        names = subs["subdomains"]
        report["subdomains"] = {"count": len(names), "names": names[:MAX_SUBDOMAINS]}
        if len(names) > MAX_SUBDOMAINS:
            report["subdomains"]["note"] = f"showing {MAX_SUBDOMAINS}, use the subdomains tool for all"

    report["highlights"] = highlights(report)
    return report
