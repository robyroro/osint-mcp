import logging
from typing import Annotated

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import mailsec, recon, sources, tlscert

# httpx logs every request at INFO, way too chatty
logging.getLogger("httpx").setLevel(logging.WARNING)

mcp = MCPServer(
    "osint",
    instructions=(
        "Passive recon tools for domains and IPs: RDAP/whois, DNS, certificate "
        "transparency, email security (SPF/DMARC/MTA-STS), TLS certificates, ASN/BGP, "
        "Wayback Machine, HTTP headers and Shodan InternetDB. Start with recon_domain "
        "for an overview. Nothing here scans or brute forces anything."
    ),
)

# every tool only reads public data, nothing gets changed anywhere
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)

Domain = Annotated[str, Field(
    description='Domain name, e.g. "example.com". A full URL works too, only the hostname is used.'
)]
IP = Annotated[str, Field(description='IPv4 or IPv6 address, e.g. "1.1.1.1" or "2606:4700::1111".')]


def _domain(value):
    try:
        return sources.clean_domain(value)
    except ValueError as e:
        raise ToolError(str(e))


def _ip(value):
    try:
        return sources.clean_ip(value)
    except ValueError:
        raise ToolError(f"not a valid ip address: {value!r}")


async def _run(coro_fn, *args, **kwargs):
    async with sources.make_client() as client:
        try:
            return await coro_fn(client, *args, **kwargs)
        except httpx.HTTPError as e:
            raise ToolError(sources.describe_error(e))


@mcp.tool(title="Domain recon", annotations=READ_ONLY)
async def recon_domain(
    domain: Domain,
    include_subdomains: Annotated[bool, Field(
        description="Look up subdomains in certificate transparency logs (crt.sh). "
                    "It's the slowest part, set false for a run that takes seconds instead of up to a minute."
    )] = True,
) -> dict:
    """Passive overview of a domain in one call: whois, DNS, email security grade,
    TLS certificate, HTTP security headers, subdomains from CT logs, and ASN /
    reverse DNS / Shodan InternetDB for its first 3 IPs. Ends with a 'highlights'
    list of things worth a look.

    Start here for general questions about a domain. Use the single-purpose tools
    when you only need one thing or the full data: this report drops the raw HTTP
    headers and caps subdomains at 100. Takes 10-60s, mostly waiting on crt.sh. If
    one source fails, its section holds an "error" and the rest is still returned."""
    async with sources.make_client() as client:
        return await recon.recon(client, _domain(domain), include_subdomains)


@mcp.tool(title="Domain whois (RDAP)", annotations=READ_ONLY)
async def domain_whois(domain: Domain) -> dict:
    """Registration info for a domain via RDAP (the JSON successor of whois):
    registrar, creation / expiry / last-changed dates, nameservers, status codes
    and abuse contact.

    Use for who registered a domain and when it expires. For who hosts it, run
    ip_whois or asn_lookup on its IPs. Some ccTLDs (.ro, .de and a few others)
    have no public RDAP and return an "error" field instead. Cached for 6h."""
    return await _run(sources.rdap_domain, _domain(domain))


@mcp.tool(title="IP whois (RDAP)", annotations=READ_ONLY)
async def ip_whois(ip: IP) -> dict:
    """Who owns an IP: network name, range and CIDRs, country, registrant org and
    abuse contact from RDAP, plus its reverse DNS (PTR) names.

    Use for the owning organisation and where to report abuse. Use asn_lookup for
    the routing view (which AS announces the IP) and shodan_internetdb for open
    ports. RDAP data is cached for 6h, the PTR lookup is live."""
    ip = _ip(ip)
    info = await _run(sources.rdap_ip, ip)
    info["ptr"] = await sources.reverse_dns(ip)
    return info


@mcp.tool(title="DNS lookup", annotations=READ_ONLY)
async def dns_lookup(
    domain: Domain,
    record_types: Annotated[list[str] | None, Field(
        description='Record types to query, e.g. ["A", "MX", "TXT"]. '
                    "Defaults to A, AAAA, CNAME, MX, NS, TXT, SOA and CAA."
    )] = None,
    nameserver: Annotated[str | None, Field(
        description='IP of the resolver to ask, e.g. "1.1.1.1", or one of the domain\'s own '
                    "nameservers to skip caches. Defaults to the system resolver."
    )] = None,
) -> dict:
    """Live DNS records for a domain, as {"records": {"A": [...], "MX": [...]}}.
    Types with no records are left out, a type that doesn't answer within 5s
    shows "<timeout>", and a domain that doesn't exist returns an NXDOMAIN error.

    Use for raw records. email_security already reads and grades the SPF / DMARC /
    DKIM TXT records, and recon_domain includes this lookup."""
    return await sources.dns_records(_domain(domain), record_types, nameserver)


@mcp.tool(title="Subdomains from CT logs", annotations=READ_ONLY)
async def subdomains(domain: Domain) -> dict:
    """Every subdomain seen in public TLS certificates, from certificate
    transparency logs via crt.sh. Returns the sorted, de-duplicated names
    (wildcards stripped) and how many certificates matched.

    The target is never contacted. Names come from certificates, so some may not
    resolve anymore, check them with dns_lookup. crt.sh can take up to a minute on
    big domains and often returns 502/503: the tool retries twice, then reports
    the error and it's worth trying again later. Cached for 6h."""
    return await _run(sources.crtsh_subdomains, _domain(domain))


@mcp.tool(title="Wayback Machine snapshots", annotations=READ_ONLY)
async def wayback(
    url: Annotated[str, Field(
        description='URL or domain to look up, e.g. "example.com/about". End it with /* '
                    '("example.com/*") to list everything archived under that path.'
    )],
    limit: Annotated[int, Field(
        description="How many snapshots to return, 1-500. Values outside that range are clamped."
    )] = 20,
    newest_first: Annotated[bool, Field(
        description="true returns the most recent snapshots, false the oldest ones."
    )] = True,
    year_from: Annotated[int | None, Field(
        description="Only snapshots from this year on, e.g. 2015. The archive starts in 1996."
    )] = None,
    year_to: Annotated[int | None, Field(
        description="Only snapshots up to and including this year."
    )] = None,
) -> dict:
    """Archived snapshots of a URL from the Wayback Machine's CDX index, each with
    timestamp, original URL, HTTP status, MIME type and an archive_url to view it.
    Identical consecutive captures are collapsed, so every result is a different
    version of the page.

    Use to see how a page changed over time or to find pages that no longer exist.
    It doesn't return page content, open archive_url for that. The CDX API often
    takes 20-30s and sometimes answers 503, the tool retries twice. Cached for 6h."""
    limit = max(1, min(limit, 500))
    return await _run(sources.wayback_snapshots, url, limit, newest_first, year_from, year_to)


@mcp.tool(title="HTTP headers", annotations=READ_ONLY)
async def http_headers(
    url: Annotated[str, Field(
        description='URL to fetch, e.g. "https://example.com/login". A bare domain gets https:// in front.'
    )],
) -> dict:
    """One GET request to a URL, following redirects. Returns the status, redirect
    chain, final URL, Server header, all response headers and which of HSTS, CSP,
    X-Content-Type-Options, X-Frame-Options, Referrer-Policy and
    Permissions-Policy are missing.

    Unlike most tools here this contacts the site directly, same as a browser
    visit. Use tls_certificate for the certificate itself. Not cached."""
    return await _run(sources.http_headers, url)


@mcp.tool(title="Shodan InternetDB", annotations=READ_ONLY)
async def shodan_internetdb(ip: IP) -> dict:
    """Open ports, hostnames, CPEs, tags and known CVEs for an IP from Shodan's
    free InternetDB. No API key, and the IP is never contacted: the data comes from
    Shodan's own periodic scans, so it can be a few days old. IPs Shodan hasn't
    scanned come back with no ports and a note.

    Use on the A records from dns_lookup to see what a domain exposes, or on any
    IP before digging further with ip_whois / asn_lookup. Cached for 6h."""
    return await _run(sources.internetdb, _ip(ip))


@mcp.tool(title="Email security grade", annotations=READ_ONLY)
async def email_security(
    domain: Domain,
    dkim_selectors: Annotated[list[str] | None, Field(
        description='DKIM selectors to check instead of the built-in common ones, e.g. ["google", "s1"]. '
                    "The s= tag in the DKIM-Signature header of an email from the domain gives the real one."
    )] = None,
) -> dict:
    """Grade (A-F) how well a domain is protected against being spoofed in email,
    with a list of issues to fix. Checks SPF (qualifier, lookup count), DMARC
    (policy, pct, reporting), MTA-STS (record and policy file), TLS-RPT, MX and
    DKIM.

    Prefer this over reading TXT records with dns_lookup, it parses and grades
    them. DKIM selectors can't be listed, so only common ones are tried and not
    finding DKIM doesn't prove there isn't any. Uses live DNS, the only HTTP
    request is for the MTA-STS policy at mta-sts.<domain>."""
    return await _run(mailsec.check, _domain(domain), dkim_selectors)


@mcp.tool(title="TLS certificate", annotations=READ_ONLY)
async def tls_certificate(
    host: Annotated[str, Field(
        description='Hostname to connect to, e.g. "example.com". It\'s also the name the '
                    "certificate is verified against. A URL works too, only the hostname is used."
    )],
    port: Annotated[int, Field(
        ge=1, le=65535,
        description="TCP port. 443 for websites, 465 / 993 / 995 for mail servers with implicit TLS.",
    )] = 443,
) -> dict:
    """Connect to host:port and read its TLS certificate: subject, issuer,
    validity dates, days until expiry, SANs, serial, negotiated TLS version and
    cipher, plus warnings (expires within 14 days, deprecated TLS version).
    Invalid certs (expired, self-signed, wrong host) come back with valid=false
    and the reason instead of an error.

    Contacts the host directly, like a browser would, 10s timeout, not cached.
    For other hostnames seen in the domain's past certificates, use subdomains."""
    return await tlscert.fetch_certificate(_domain(host), port)


@mcp.tool(title="ASN / BGP lookup", annotations=READ_ONLY)
async def asn_lookup(
    query: Annotated[str, Field(
        description='An IP address ("1.1.1.1") or an AS number, with or without the AS prefix ("AS13335" or "13335").'
    )],
    include_prefixes: Annotated[bool, Field(
        description="Also list the prefixes the AS announces. Set false when you only need the holder."
    )] = True,
) -> dict:
    """Look up an IP or AS number via RIPEstat: which AS announces it (and the
    covering prefix for an IP), who holds the AS, whether it's announced right
    now, and the prefixes it announces (first 100, IPv4 then IPv6, with totals).
    Works for every RIR, not only RIPE.

    Use to find the hosting / network provider behind an IP or to map an
    organisation's address space. Use ip_whois for the registration record and
    abuse contact. Cached for 6h."""
    try:
        sources.parse_asn_query(query)
    except ValueError as e:
        raise ToolError(str(e))
    return await _run(sources.asn_info, query, include_prefixes)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
