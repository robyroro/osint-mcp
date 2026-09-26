# osint-mcp

MCP server that gives Claude (or any MCP client) a handful of passive recon lookups for domains and IPs. No API keys needed, everything comes from public sources.

I got tired of jumping between whois, crt.sh, the Wayback Machine and Shodan tabs when looking into a domain, so this lets the model do it and put the results together.

## Tools

| tool | what it does | source |
|---|---|---|
| `domain_whois` | registrar, created/expires, nameservers, abuse contact | RDAP (rdap.org) |
| `ip_whois` | network owner, CIDR, country, abuse contact, PTR | RDAP + reverse DNS |
| `dns_lookup` | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA (or pick your own) | your resolver or a custom one |
| `subdomains` | subdomains found in certificate transparency logs | crt.sh |
| `wayback` | archived snapshots of a URL, supports `example.com/*` | Wayback CDX API |
| `http_headers` | status, redirect chain, headers, missing security headers | direct request |
| `shodan_internetdb` | open ports, hostnames, CPEs, known CVEs | Shodan InternetDB (free) |

Everything except `http_headers` is passive, the target never sees your traffic. `http_headers` is just a normal GET request, same as opening the page in a browser.

## Install

Needs Python 3.10+.

```
pip install git+https://github.com/robyroro/osint-mcp
```

or if you use uv you don't need to install anything, just point the client at `uvx` (see below).

### Claude Desktop

Add this to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osint": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/robyroro/osint-mcp", "osint-mcp"]
    }
  }
}
```

If you installed with pip, `"command": "osint-mcp"` with no args works too.

### Claude Code

```
claude mcp add osint -- uvx --from git+https://github.com/robyroro/osint-mcp osint-mcp
```

Cursor, Windsurf etc. take the same JSON as Claude Desktop.

## Example prompts

- "what can you find about example.com? registrar, dns, subdomains, anything interesting"
- "check the security headers on these 5 sites and tell me which are worst"
- "which of the subdomains of example.com resolve to something with open ports?"
- "what did example.com/about look like in 2015?"

## Notes

- crt.sh and the Wayback CDX API are slow and return 502/503 pretty often. The server retries a couple of times but sometimes you just have to try again later.
- InternetDB isn't real-time and only has IPs Shodan has actually scanned.
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
