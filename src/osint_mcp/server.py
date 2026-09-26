import logging

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

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


@mcp.tool()
async def recon_domain(domain: str, include_subdomains: bool = True) -> dict:
    """Passive overview of a domain in one call: whois, DNS, email security grade,
    TLS certificate, HTTP security headers, subdomains from CT logs, and ASN /
    reverse DNS / Shodan InternetDB for its first few IPs. Ends with a
    'highlights' list of things worth a look. Takes 10-60s, mostly waiting on
    crt.sh, pass include_subdomains=false for a faster run."""
    async with sources.make_client() as client:
        return await recon.recon(client, _domain(domain), include_subdomains)


@mcp.tool()
async def domain_whois(domain: str) -> dict:
    """Registration info for a domain via RDAP: registrar, creation/expiry dates,
    nameservers, status and abuse contact."""
    return await _run(sources.rdap_domain, _domain(domain))


@mcp.tool()
async def ip_whois(ip: str) -> dict:
    """Who owns an IP: network name, CIDR, country, org, abuse contact and
    reverse DNS (PTR)."""
    ip = _ip(ip)
    info = await _run(sources.rdap_ip, ip)
    info["ptr"] = await sources.reverse_dns(ip)
    return info


@mcp.tool()
async def dns_lookup(domain: str, record_types: list[str] | None = None, nameserver: str | None = None) -> dict:
    """DNS records for a domain. Defaults to A, AAAA, CNAME, MX, NS, TXT, SOA, CAA.
    Pass nameserver (e.g. "1.1.1.1") to query a specific resolver."""
    return await sources.dns_records(_domain(domain), record_types, nameserver)


@mcp.tool()
async def subdomains(domain: str) -> dict:
    """Subdomains seen in public TLS certificates (crt.sh). Can be slow for
    large domains."""
    return await _run(sources.crtsh_subdomains, _domain(domain))


@mcp.tool()
async def wayback(
    url: str,
    limit: int = 20,
    newest_first: bool = True,
    year_from: int | None = None,
    year_to: int | None = None,
) -> dict:
    """Archived snapshots of a URL from the Wayback Machine. Use a wildcard like
    "example.com/*" to list everything archived under a site."""
    limit = max(1, min(limit, 500))
    return await _run(sources.wayback_snapshots, url, limit, newest_first, year_from, year_to)


@mcp.tool()
async def http_headers(url: str) -> dict:
    """Fetch a URL and return status, redirect chain, response headers and which
    common security headers are missing."""
    return await _run(sources.http_headers, url)


@mcp.tool()
async def shodan_internetdb(ip: str) -> dict:
    """Open ports, hostnames, CPEs, tags and known CVEs for an IP from Shodan's
    free InternetDB (no API key, data can be a few days old)."""
    return await _run(sources.internetdb, _ip(ip))


@mcp.tool()
async def email_security(domain: str, dkim_selectors: list[str] | None = None) -> dict:
    """Grade (A-F) how well a domain is protected against being spoofed in email:
    SPF, DMARC, MTA-STS, TLS-RPT and DKIM. DKIM selectors can't be listed, so a
    set of common ones is tried unless you pass your own."""
    return await _run(mailsec.check, _domain(domain), dkim_selectors)


@mcp.tool()
async def tls_certificate(host: str, port: int = 443) -> dict:
    """Connect to host:port and read its TLS certificate: issuer, validity dates,
    days until expiry, SANs, negotiated TLS version. Invalid certs (expired,
    self-signed, wrong host) are reported with the reason."""
    return await tlscert.fetch_certificate(_domain(host), port)


@mcp.tool()
async def asn_lookup(query: str, include_prefixes: bool = True) -> dict:
    """Look up an IP or AS number (e.g. "AS13335") via RIPEstat: which AS
    announces it, who holds the AS and every prefix it announces."""
    try:
        sources.parse_asn_query(query)
    except ValueError as e:
        raise ToolError(str(e))
    return await _run(sources.asn_info, query, include_prefixes)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
