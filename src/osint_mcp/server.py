import logging

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import mailsec, sources

# httpx logs every request at INFO, way too chatty
logging.getLogger("httpx").setLevel(logging.WARNING)

mcp = MCPServer(
    "osint",
    instructions=(
        "Passive recon tools for domains and IPs: RDAP/whois, DNS, certificate "
        "transparency, Wayback Machine, HTTP headers and Shodan InternetDB. "
        "Nothing here scans or brute forces anything."
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
        except httpx.HTTPStatusError as e:
            raise ToolError(f"{e.request.url.host} returned {e.response.status_code}")
        except httpx.TimeoutException as e:
            raise ToolError(f"timed out talking to {e.request.url.host}, try again")
        except httpx.RequestError as e:
            raise ToolError(f"request failed: {e}")


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


def main():
    mcp.run()


if __name__ == "__main__":
    main()
