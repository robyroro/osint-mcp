"""Small investigations assembled from the same public lookups as the basic tools."""

import asyncio
import re
from collections import defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urljoin

import httpx
import tldextract

from . import evidence, network, recon, sources

_suffixes = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
LEGAL_WORDS = (
    "contact",
    "about",
    "terms",
    "privacy",
    "refund",
    "returns",
    "termeni",
    "confidentialitate",
    "retur",
    "despre",
)


def site_domain(host):
    parts = _suffixes(host)
    return parts.top_domain_under_public_suffix or host


def domains(values, maximum=10, minimum=1):
    if not minimum <= len(values) <= maximum:
        raise ValueError(f"use between {minimum} and {maximum} domains")
    return list(dict.fromkeys(sources.clean_domain(value) for value in values))


async def batch(client, values, include_subdomains=False, include_active=False):
    selected = domains(values)
    slots = asyncio.Semaphore(3)

    async def one(domain):
        async with slots:
            try:
                return await asyncio.wait_for(
                    recon.recon(client, domain, include_subdomains, include_active),
                    timeout=90,
                )
            except asyncio.TimeoutError:
                return {"domain": domain, "error": "recon exceeded the 90 second deadline"}
            except (httpx.HTTPError, ValueError) as error:
                return {"domain": domain, "error": sources.describe_error(error)}

    reports = await asyncio.gather(*(one(domain) for domain in selected))
    return {
        "count": len(reports),
        "reports": reports,
        "incomplete_domains": [
            r["domain"]
            for r in reports
            if r.get("error")
            or any(status in ("error", "partial") for status in r.get("coverage", {}).values())
        ],
        "note": "At most three domains run at once. Individual source failures stay in each report.",
    }


async def compare(client, values):
    selected = domains(values, maximum=6, minimum=2)
    if len(selected) < 2:
        raise ValueError("use at least two different domains")

    async def one(domain):
        result = await recon._gather(
            {
                "whois": sources.rdap_domain(client, domain),
                "dns": sources.dns_records(domain),
            }
        )
        return {"domain": domain, **result}

    reports = await asyncio.gather(*(one(domain) for domain in selected))
    owners = defaultdict(set)
    for report in reports:
        domain = report["domain"]
        dns = report["dns"].get("records", {})
        for kind, values in (
            ("ip", dns.get("A", []) + dns.get("AAAA", [])),
            ("nameserver", dns.get("NS", [])),
            ("mail_server", dns.get("MX", [])),
        ):
            for value in values:
                if value.startswith("<"):
                    continue
                if kind == "ip" and not recon._is_ip(value):
                    continue
                if kind == "mail_server":
                    value = value.split()[-1]
                    if value == ".":
                        continue
                owners[(kind, value.lower().rstrip("."))].add(domain)
        registrar = report["whois"].get("registrar")
        if registrar:
            owners[("registrar", registrar)].add(domain)
    shared = [
        {"kind": kind, "value": value, "domains": sorted(linked)}
        for (kind, value), linked in sorted(owners.items())
        if len(linked) > 1
    ]
    unavailable = [
        {"domain": r["domain"], "check": kind, "error": r[kind]["error"]}
        for r in reports
        for kind in ("whois", "dns")
        if r[kind].get("error")
    ] + [
        {"domain": r["domain"], "check": "dns." + kind, "error": value}
        for r in reports
        for kind, values in r["dns"].get("records", {}).items()
        for value in values
        if value.startswith("<")
    ]
    return {
        "domains": selected,
        "shared": shared,
        "reports": reports,
        "unavailable": unavailable,
        "note": "A shared IP, mail server, nameserver or registrar can come from a hosting provider. "
        "These are leads to investigate, not evidence that the sites have the same owner.",
    }


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.in_title = False
        self.title = []
        self.text = []
        self.links = []
        self.forms = []
        self.password_field = False
        self.description = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style"):
            self.skip += 1
        if tag == "title":
            self.in_title = True
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "form":
            self.forms.append(attrs.get("action", ""))
        if tag == "input" and attrs.get("type", "").lower() == "password":
            self.password_field = True
        if tag == "meta" and attrs.get("name", "").lower() == "description":
            self.description = attrs.get("content", "")[:500]

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if not self.skip:
            self.text.append(data)
            if self.in_title:
                self.title.append(data)


def parse_page(html, url):
    parser = Page()
    parser.feed(html)
    text = re.sub(r"\s+", " ", " ".join(parser.text))
    origin = network.normalize_url(url)
    links, legal = set(), set()
    for href in parser.links:
        try:
            link = network.normalize_url(urljoin(url, href))
        except (ValueError, httpx.InvalidURL):
            continue
        links.add(str(link))
        if (link.scheme, link.host, link.port) == (origin.scheme, origin.host, origin.port) and any(
            word in link.path.casefold() for word in LEGAL_WORDS
        ):
            legal.add(str(link.copy_with(query=None)))
    identifiers = [
        {"label": match.group(1), "value": match.group(2)}
        for match in re.finditer(
            r"\b(CUI|CIF|VAT(?:\s*(?:ID|number))?|company\s*(?:number|no))\s*[:#.]?\s*([A-Z]{0,2}\s*\d[\d .-]{3,18}\d)",
            text,
            re.IGNORECASE,
        )
    ]
    forms = []
    for action in parser.forms:
        try:
            forms.append(str(network.normalize_url(urljoin(url, action))))
        except ValueError:
            continue
    return {
        "title": " ".join(parser.title)[:300],
        "description": parser.description,
        "legal_links": sorted(legal)[:20],
        "company_identifiers": identifiers[:20],
        "external_link_domains": sorted(
            {
                network.normalize_url(link).host
                for link in links
                if network.normalize_url(link).host != origin.host
            }
        )[:30],
        "form_actions": list(dict.fromkeys(forms))[:10],
        "password_field": parser.password_field,
    }


async def page_details(client, url, follow_legal=True):
    response = await network.read_limited(
        client, str(network.normalize_url(url)), max_bytes=512 * 1024
    )
    evidence.record(
        "Website page",
        str(response.url),
        status=str(response.status_code),
        fetched_at=evidence.now(),
    )
    response.raise_for_status()
    content_type = response.headers.get("content-type", "").split(";")[0].lower()
    if content_type and content_type not in ("text/html", "application/xhtml+xml"):
        return {"url": str(response.url), "error": f"expected HTML, got {content_type}"}
    page = parse_page(response.text, str(response.url))
    page.update(
        url=str(response.url),
        status=response.status_code,
        pages_checked=[str(response.url)],
        page_errors=[],
    )
    if follow_legal:
        origin = network.normalize_url(str(response.url))
        for link in page["legal_links"][:3]:
            try:
                # Stop a legal-page redirect before requesting a different site.
                current = network.normalize_url(link)
                for _ in range(6):
                    if (current.scheme, current.host, current.port) != (
                        origin.scheme,
                        origin.host,
                        origin.port,
                    ):
                        raise ValueError("legal page redirected to a different origin")
                    sub = await network.read_limited(
                        client, str(current), max_bytes=512 * 1024, follow_redirects=False
                    )
                    if sub.is_redirect and sub.headers.get("location"):
                        current = network.normalize_url(
                            urljoin(str(current), sub.headers["location"])
                        )
                        continue
                    break
                else:
                    raise ValueError("too many legal-page redirects")
                evidence.record(
                    "Legal page",
                    str(sub.url),
                    status=str(sub.status_code),
                    fetched_at=evidence.now(),
                )
                sub.raise_for_status()
                extra = parse_page(sub.text, str(sub.url))
                page["pages_checked"].append(str(sub.url))
                page["company_identifiers"].extend(extra["company_identifiers"])
            except (httpx.HTTPError, ValueError) as error:
                page["page_errors"].append({"url": link, "error": sources.describe_error(error)})
    page["company_identifiers"] = [
        dict(label=label, value=value)
        for label, value in dict.fromkeys(
            (item["label"], item["value"]) for item in page["company_identifiers"]
        )
    ][:20]
    return page


def signals(report, reference_domain=None):
    findings = []

    def add(kind, message, path):
        findings.append({"kind": kind, "message": message, "evidence_path": path})

    page, details = report["page"], report["recon"]
    if not page.get("error"):
        if not page["url"].startswith("https://"):
            add("concern", "The page is served over HTTP.", "page.url")
            if page.get("password_field"):
                add("concern", "The HTTP page contains a password field.", "page.password_field")
        if not page.get("legal_links"):
            add(
                "context",
                "No contact or legal links were found in this page HTML.",
                "page.legal_links",
            )
        if page.get("company_identifiers"):
            add(
                "context",
                "The site displays company identifiers. They have not been checked against a registry.",
                "page.company_identifiers",
            )
    tls = details.get("tls", {})
    if tls.get("valid") is False:
        add(
            "concern",
            f"The TLS certificate could not be verified: {tls.get('error', 'unknown reason')}",
            "recon.tls",
        )
    registered = details.get("whois", {}).get("registered")
    if report.get("archive", {}).get("count") == 0:
        add(
            "context",
            "The archive returned no captures for this query. That does not establish the site age.",
            "archive",
        )
    if registered:
        try:
            created = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            if 0 <= age < 90:
                add(
                    "context",
                    f"The domain was registered {age} days ago. New domains can be legitimate.",
                    "recon.whois.registered",
                )
        except (TypeError, ValueError):
            pass
    if reference_domain:
        actual = site_domain(report["domain"])
        expected = site_domain(sources.clean_domain(reference_domain))
        ratio = SequenceMatcher(None, actual, expected).ratio()
        report["reference_comparison"] = {
            "actual": actual,
            "reference": expected,
            "similarity": round(ratio, 3),
            "same_domain": actual == expected,
        }
        if actual != expected and ratio >= 0.7:
            add(
                "context",
                f"The domain resembles {expected}, but is a different registrable domain. "
                "Check the URL against a trusted source.",
                "reference_comparison",
            )
    return findings


async def investigate(client, url, reference_domain=None, follow_legal=True):
    url = str(network.normalize_url(url))
    domain = sources.clean_domain(url)
    gathered = await recon._gather(
        {
            "page": page_details(client, url, follow_legal),
            "recon": recon.recon(client, domain, include_subdomains=False),
            "archive": sources.wayback_snapshots(
                client, site_domain(domain), limit=5, newest_first=False
            ),
        }
    )
    report = {"url": url, "domain": domain, **gathered}
    report["signals"] = signals(report, reference_domain)
    report["unavailable"] = (
        [
            {"check": name, "error": value["error"]}
            for name, value in gathered.items()
            if value.get("error")
        ]
        + [
            {"check": "recon." + name, "error": value["error"]}
            for name, value in gathered["recon"].items()
            if isinstance(value, dict) and value.get("error")
        ]
        + [{"check": "legal_page", **item} for item in gathered["page"].get("page_errors", [])]
        + [
            {"check": "recon." + name, "error": "only part of this check completed"}
            for name, status in gathered["recon"].get("coverage", {}).items()
            if status == "partial"
        ]
    )
    report["assessment"] = "incomplete" if report["unavailable"] else "signals_collected"
    report["note"] = (
        "This report cannot verify deliveries, reviews, product availability or company ownership. "
    )
    report["note"] += (
        "A valid certificate, an old domain or a company number does not prove a shop is trustworthy."
    )
    return report


async def certificates(client, domain, limit=50):
    if not 1 <= limit <= 100:
        raise ValueError("certificate limit must be between 1 and 100")
    _, rows = await sources.fetch_json(
        client,
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        retries=2,
        timeout=60.0,
    )
    certs = {}
    for row in rows or []:
        names = sources.parse_crtsh([row], domain)
        cert_id = row.get("id")
        if names and cert_id is not None:
            certs[cert_id] = {
                "id": cert_id,
                "names": names[:100],
                "names_truncated": len(names) > 100,
                "issuer": row.get("issuer_name"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "logged_at": row.get("entry_timestamp"),
                "url": f"https://crt.sh/?id={cert_id}",
            }
    ordered = sorted(
        certs.values(), key=lambda cert: (cert["logged_at"] or "", str(cert["id"])), reverse=True
    )
    return {
        "domain": domain,
        "count": len(ordered),
        "certificates": ordered[:limit],
        "truncated": len(ordered) > limit,
        "note": "CT records show issuance history, not the certificate currently served by the site. "
        "The count covers the rows returned by crt.sh, not a guaranteed complete history.",
    }
