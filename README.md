# osint-mcp

[![tests](https://github.com/robyroro/osint-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/robyroro/osint-mcp/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/osint-mcp-server)](https://pypi.org/project/osint-mcp-server/)

MCP server that gives Claude (or any MCP client) a handful of passive recon lookups for domains and IPs. No API keys needed, everything comes from public sources.

I got tired of jumping between whois, crt.sh, the Wayback Machine and Shodan tabs when looking into a domain, so this lets the model do it and put the results together.

## Tools

| tool | what it does | source |
|---|---|---|
| `recon_domain` | all of the below at once + a list of highlights worth a look | everything |
| `domain_whois` | registrar, created/expires, nameservers, abuse contact | RDAP (rdap.org) |
| `ip_whois` | network owner, CIDR, country, abuse contact, PTR | RDAP + reverse DNS |
| `dns_lookup` | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA (or pick your own) | your resolver or a custom one |
| `subdomains` | subdomains found in certificate transparency logs | crt.sh |
| `wayback` | archived snapshots of a URL, supports `example.com/*` | Wayback CDX API |
| `http_headers` | status, redirect chain, headers, missing security headers | direct request |
| `shodan_internetdb` | open ports, hostnames, CPEs, known CVEs | Shodan InternetDB (free) |
| `email_security` | SPF, DMARC, MTA-STS, TLS-RPT, DKIM, graded A-F | DNS |
| `tls_certificate` | issuer, expiry, SANs, TLS version, why a cert is invalid | direct connection |
| `asn_lookup` | which AS announces an IP, who owns it, all its prefixes | RIPEstat |

Everything except `http_headers` and `tls_certificate` is passive, the target never sees your traffic. Those two just open a normal connection, same as visiting the site in a browser.

## Install

Needs Python 3.10+.

```
pip install osint-mcp-server
```

or if you use uv you don't need to install anything, just point the client at `uvx` (see below).

### Claude Desktop

Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osint": {
      "command": "uvx",
      "args": ["osint-mcp-server"]
    }
  }
}
```

If you installed with pip, `"command": "osint-mcp-server"` with no args works too.

### Claude Code

```
claude mcp add osint -- uvx osint-mcp-server
```

Cursor, Windsurf etc. take the same JSON as Claude Desktop.

## Example prompts

- "run recon on example.com and tell me what stands out"
- "can someone spoof email from our domain? what should we fix first?"
- "which of these 20 domains have certificates expiring this month?"
- "what ip ranges does AS13335 announce?"
- "check the security headers on these 5 sites and tell me which are worst"
- "which of the subdomains of example.com resolve to something with open ports?"
- "what did example.com/about look like in 2015?"

## Caching

API responses (RDAP, crt.sh, Wayback, RIPEstat, InternetDB) are cached in sqlite for 6 hours at `~/.cache/osint-mcp/cache.sqlite3`, mostly so crt.sh doesn't get hammered. DNS, TLS and HTTP checks are always live.

```
OSINT_MCP_CACHE=off           # disable
OSINT_MCP_CACHE_TTL=3600      # seconds
OSINT_MCP_CACHE_PATH=/tmp/x.db
```

## Notes

- crt.sh and the Wayback CDX API are slow and return 502/503 pretty often. The server retries a couple of times but sometimes you just have to try again later.
- InternetDB isn't real-time and only has IPs Shodan has actually scanned.
- DKIM selectors can't be listed, `email_security` tries the common ones. Pass `dkim_selectors` if you know yours.
- `.ro`, `.de` and some other ccTLDs don't have public RDAP, so `domain_whois` can't do much for them.

## Development

```
git clone https://github.com/robyroro/osint-mcp
cd osint-mcp
pip install -e . pytest
pytest
```

Tests don't hit the network, HTTP calls are mocked.

To poke at it with the MCP inspector:

```
npx @modelcontextprotocol/inspector osint-mcp
```

## Be reasonable

This only pulls public data, but still: use it on your own stuff, bug bounty targets that are in scope, or for research. Don't use it to go after people.

## License

MIT

<!-- mcp-name: io.github.robyroro/osint-mcp -->
