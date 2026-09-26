# Changelog

## 0.2.0

- `recon_domain`: runs everything at once and ends with a list of highlights. one failing source doesn't break the report anymore, it just shows the error in that section
- `email_security`: SPF / DMARC / MTA-STS / TLS-RPT / DKIM with an A-F grade and a list of what to fix
- `tls_certificate`: issuer, expiry, SANs, negotiated TLS version, and the actual reason when a cert is invalid
- `asn_lookup`: AS number, holder and announced prefixes via RIPEstat
- sqlite cache for API responses (6h by default, see README)
- `domain_whois` explains itself when the TLD has no RDAP instead of just saying 404

## 0.1.0

First release: `domain_whois`, `ip_whois`, `dns_lookup`, `subdomains`, `wayback`, `http_headers`, `shodan_internetdb`.
