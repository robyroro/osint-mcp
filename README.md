# osint-mcp

[![tests](https://github.com/robyroro/osint-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/robyroro/osint-mcp/actions/workflows/tests.yml)
[![PyPI](https://img.shields.io/pypi/v/osint-mcp-server)](https://pypi.org/project/osint-mcp-server/)

MCP tools for investigating domains, IPs and websites. Look up public records, compare infrastructure, check several domains at once, or collect the details behind a suspicious site. No API keys needed.

I got tired of jumping between whois, crt.sh, the Wayback Machine and Shodan tabs when looking into a domain, so this lets the model do it and put the results together.

## Tools

| tool | what it does | source |
|---|---|---|
| `recon_domain` | domain overview, highlights and coverage for each check | RDAP, DNS, email, CT logs, HTTP, TLS, RIPEstat and InternetDB |
| `recon_batch` | up to ten domain reports, with three running at a time and source failures kept in each report | public APIs + DNS; direct checks are optional |
| `compare_domains` | shared IPs, nameservers, mail servers and registrars, with the records behind each match | DNS + RDAP |
| `investigate_site` | page details, displayed company IDs, legal/contact pages, registration, archive captures, HTTP and TLS, with concrete signals and missing checks | website + public sources |
| `certificate_history` | certificate issuers, validity dates, related names and links to the CT entries | crt.sh |
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

`http_headers`, `tls_certificate` and `investigate_site` contact the site directly. `email_security` can fetch its MTA-STS policy. `recon_domain` includes these direct checks by default; set `include_active=false` to skip HTTP, TLS and the MTA-STS policy fetch.

`recon_batch` starts with direct checks off. `compare_domains` uses public APIs and DNS only. DNS lookups still involve resolvers and may reach the domain's authoritative nameservers. There are no port scans, directory brute forcing, form submissions or browser scripts.

## Investigations

For a single domain, start with `recon_domain`. Its `coverage` field says which checks succeeded, failed, returned partial data or were skipped. A broken source leaves an error in that section; it does not erase the other results. IPv4 and IPv6 addresses are both considered, with details for at most three addresses.

For a portfolio or a list of domains, use `recon_batch`. It accepts up to ten entries, removes duplicate hostnames and limits work to three domains at a time. Each domain has a 90 second deadline. `incomplete_domains` makes failures easy to find. Subdomain history and direct connections are both off by default.

For possible links between sites, use `compare_domains`. It reports shared infrastructure, not a common-owner verdict. A CDN address, Google mail server or popular registrar can appear on thousands of unrelated domains. Failed DNS and RDAP checks stay visible rather than being treated as a clean result.

For a website or shop that needs checking, use `investigate_site`. It reads the supplied page and, optionally, up to three linked contact/legal pages on the same origin. It extracts the title, description, displayed company identifiers, form destinations and linked domains, then combines those details with the public lookups. HTML is read as text; scripts, forms and linked assets are never executed.

The report has `signals`, each pointing to its evidence, and an `unavailable` list. Its `assessment` is either `signals_collected` or `incomplete`. Neither means the site is safe. It cannot confirm deliveries, reviews, products or ownership of a company number. A number copied into a footer is only an observed claim, not a verified registration.

An optional `reference_domain` compares the spelling against a domain you already trust. Public suffixes, including private suffixes such as `github.io`, come from the package's bundled list without a download. Similar spelling is a reason to check the URL, not proof of impersonation.

`certificate_history` reads issuance records from crt.sh and reports duplicate IDs and truncation. It does not tell you which certificate is served now; use `tls_certificate` for that.

## Sources and freshness

MCP results include `checked_at`, an `evidence` list and a notice that external text is untrusted data. Evidence records contain the source URL, response status, collection time and whether the response came from cache. DNS evidence identifies the queried name and resolver type.

`checked_at` is the report time. `fetched_at` is when this tool obtained the source response, not when the provider last updated its underlying data. Cached responses retain their earlier collection time and expiry. Cache entries made before 0.3.0 have an unknown collection time until fetched again.

Records, page titles and other external strings can contain misleading text or instructions. They are evidence to inspect, never instructions for the connected agent. The final interpretation still belongs to the investigator.

Direct requests accept public HTTP/HTTPS destinations only. Private, local, multicast and reserved addresses are blocked, including redirect destinations. Connections use a checked DNS address while preserving the hostname for HTTP and TLS. HTTP headers are read without downloading the final page body. JSON responses are limited to 8 MiB; site pages to 512 KiB; MTA-STS policies to 64 KiB. Legal-page redirects cannot leave the original origin. Environment proxies are not used.

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

### Updating

For a pip installation:

```sh
python -m pip install --upgrade osint-mcp-server
```

For a client that launches `uvx`, use `osint-mcp-server@latest` in `args` when you want uv to check for the latest package. Use `osint-mcp-server@0.3.0` to pin this release. Restart the MCP server after updating. Existing pip installations do not update themselves.

Allow at least 120 seconds for individual investigations and 360 seconds for a full batch in clients with configurable tool timeouts. crt.sh and Wayback can take longer after retries; use the smaller tools when you only need one answer.

## Example prompts

- "run recon on example.com and tell me what stands out"
- "can someone spoof email from our domain? what should we fix first?"
- "which of these 20 domains have certificates expiring this month?"
- "what ip ranges does AS13335 announce?"
- "check the security headers on these 5 sites and tell me which are worst"
- "which of the subdomains of example.com resolve to something with open ports?"
- "what did example.com/about look like in 2015?"
- "compare these three shops: do they share hosting, mail servers or a registrar? show the actual matches"
- "investigate this shop URL, include the contact pages, and tell me which checks couldn't finish"
- "does examp1e.com resemble example.com? collect the evidence without calling it a scam"
- "run recon on these ten domains without connecting to their websites"
- "show the last twenty certificate entries for this domain and which names they contain"

## Caching

API responses (RDAP, crt.sh, Wayback, RIPEstat, InternetDB) are cached in sqlite for 6 hours at `~/.cache/osint-mcp/cache.sqlite3`, mostly so crt.sh doesn't get hammered. DNS, TLS and HTTP checks are always live.

```
OSINT_MCP_CACHE=off           # disable
OSINT_MCP_CACHE_TTL=3600      # seconds
OSINT_MCP_CACHE_PATH=/tmp/x.db
```

## Notes

- crt.sh and the Wayback CDX API are slow and return 502/503 pretty often. The server retries a couple of times; an individual request can take up to three minutes after retries. A batch domain stops after 90 seconds instead.
- InternetDB isn't real-time and only has IPs Shodan has actually scanned.
- DKIM selectors can't be listed, `email_security` tries the common ones. Pass `dkim_selectors` if you know yours.
- Some TLDs return no RDAP data through rdap.org. A missing response does not establish that the domain is unregistered.
- Site checks read server-rendered HTML. Content loaded only by JavaScript will not appear. The tool does not bypass bot blocks or log in.

## Development

```
git clone https://github.com/robyroro/osint-mcp
cd osint-mcp
pip install -e . pytest ruff build
ruff check src tests
pytest
python -m build
```

Tests use synthetic data and mocked network responses. They include a real MCP stdio handshake, source failures, cache migration, bounded batches and blocked network destinations. CI runs Python 3.10, 3.12 and 3.14 on Linux and Windows.

The publishing workflow runs on `v*` tags. It checks the version, runs tests, builds the package, publishes to PyPI and then updates the official MCP Registry. A GitHub push alone does not update an installed package or a directory's description.

To poke at it with the MCP inspector:

```
npx @modelcontextprotocol/inspector osint-mcp
```

## Be reasonable

This only pulls public data, but still: use it on your own stuff, bug bounty targets that are in scope, or for research. Don't use it to go after people.

## License

MIT © [Robert Vind-Gardoș](https://stratagency.ro/en/robert-vind-gardos) ([@robyroro](https://github.com/robyroro))

<!-- mcp-name: io.github.robyroro/osint-mcp -->
