# Changelog

## 0.3.0

- `recon_batch` checks up to ten domains, with three running at once, a per-domain deadline and incomplete checks called out.
- `compare_domains` finds shared IPs, nameservers, mail servers and registrars without assuming the sites have the same owner.
- `investigate_site` reads a page and up to three contact/legal pages, collects public domain records and archive captures, and returns signals with their evidence and missing checks.
- `certificate_history` returns deduplicated CT entries with issuers, dates, names and certificate links.
- Recon can skip direct web connections and now considers IPv6 as well as IPv4. DNS timeouts are marked as partial results.
- MCP responses carry source URLs, collection times and cache freshness. Old cache databases are migrated without losing their entries.
- HTTP and TLS connections are restricted to public addresses. DNS is pinned before connecting, redirects are checked and response bodies are bounded.
- The site parser uses an offline public suffix list for brand-domain comparisons. External text is explicitly treated as untrusted data.
- Package, registry and runtime versions now agree. Tests run on Linux and Windows and include a stdio client session.

## 0.2.2

- every tool parameter has a description now, and each tool says when to use it vs the others, how slow it is and what's cached
- tools are marked read-only / non-destructive (MCP tool annotations) and have titles
- `tls_certificate` rejects ports outside 1-65535 up front
- `glama.json` so the Glama listing can be claimed

## 0.2.1

- package metadata: author name and link, no code changes

## 0.2.0

- `recon_domain`: runs everything at once and ends with a list of highlights. one failing source doesn't break the report anymore, it just shows the error in that section
- `email_security`: SPF / DMARC / MTA-STS / TLS-RPT / DKIM with an A-F grade and a list of what to fix
- `tls_certificate`: issuer, expiry, SANs, negotiated TLS version, and the actual reason when a cert is invalid
- `asn_lookup`: AS number, holder and announced prefixes via RIPEstat
- sqlite cache for API responses (6h by default, see README)
- `domain_whois` explains itself when the TLD has no RDAP instead of just saying 404

## 0.1.0

First release: `domain_whois`, `ip_whois`, `dns_lookup`, `subdomains`, `wayback`, `http_headers`, `shodan_internetdb`.
