import asyncio
import ipaddress
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx

from .cache import get_cache

USER_AGENT = "osint-mcp/0.2 (+https://github.com/robyroro/osint-mcp)"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def make_client(timeout=15.0):
    return httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        follow_redirects=True,
    )


async def get_flaky(client, url, retries=2, **kwargs):
    # crt.sh and archive.org both hand out 502/503s under load,
    # a retry or two usually gets through
    for attempt in range(retries + 1):
        r = await client.get(url, **kwargs)
        if r.status_code not in (502, 503, 504) or attempt == retries:
            return r
        await asyncio.sleep(2 * (attempt + 1))


async def fetch_json(client, url, params=None, retries=0, ok=(200,), **kwargs):
    """GET + json with the sqlite cache in front. Returns (status, data).
    Statuses outside `ok` raise, same as raise_for_status()."""
    cache = get_cache()
    key = cache.key(url, params)
    hit = cache.get(key)
    if hit is not None:
        return hit

    r = await get_flaky(client, url, retries=retries, params=params, **kwargs)
    if r.status_code not in ok:
        r.raise_for_status()
    data = r.json() if r.content else None
    cache.set(key, r.status_code, data)
    return r.status_code, data


def clean_domain(value: str) -> str:
    """Accepts 'example.com', 'https://Example.com/x', 'www.example.com.' etc."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0]
    value = value.strip(".").lower()
    if not value or "." not in value:
        raise ValueError(f"doesn't look like a domain: {value!r}")
    return value


def clean_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


# --- RDAP (the json replacement for whois) ---

def _vcard_name(entity):
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for field in vcard[1]:
        if field[0] == "fn":
            return field[3] or None
    return None


def _vcard_email(entity):
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for field in vcard[1]:
        if field[0] == "email":
            return field[3]
    return None


def _walk_entities(entities):
    # abuse contacts are usually nested under the registrar/registrant
    for e in entities or []:
        yield e
        yield from _walk_entities(e.get("entities"))


def parse_rdap_domain(data: dict) -> dict:
    events = {e["eventAction"]: e.get("eventDate") for e in data.get("events", [])}
    out = {
        "domain": (data.get("ldhName") or "").lower(),
        "status": data.get("status", []),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": sorted(
            ns["ldhName"].lower() for ns in data.get("nameservers", []) if ns.get("ldhName")
        ),
        "registrar": None,
        "abuse_email": None,
    }
    for e in _walk_entities(data.get("entities")):
        roles = e.get("roles", [])
        if "registrar" in roles and not out["registrar"]:
            out["registrar"] = _vcard_name(e)
        if "abuse" in roles and not out["abuse_email"]:
            out["abuse_email"] = _vcard_email(e)
    return out


def parse_rdap_ip(data: dict) -> dict:
    cidrs = []
    for c in data.get("cidr0_cidrs", []):
        prefix = c.get("v4prefix") or c.get("v6prefix")
        if prefix:
            cidrs.append(f"{prefix}/{c.get('length')}")

    out = {
        "network": data.get("name"),
        "handle": data.get("handle"),
        "range": f"{data.get('startAddress')} - {data.get('endAddress')}",
        "cidrs": cidrs,
        "country": data.get("country"),
        "org": None,
        "abuse_email": None,
    }
    for e in _walk_entities(data.get("entities")):
        roles = e.get("roles", [])
        if "registrant" in roles and not out["org"]:
            out["org"] = _vcard_name(e)
        if "abuse" in roles and not out["abuse_email"]:
            out["abuse_email"] = _vcard_email(e)
    return out


async def rdap_domain(client, domain):
    status, data = await fetch_json(client, f"https://rdap.org/domain/{domain}", ok=(200, 404))
    if status == 404:
        return {
            "domain": domain,
            "error": "no RDAP data. either not registered or the TLD has no public "
                     "RDAP server (.ro, .de and a few other ccTLDs), use their web whois",
        }
    return parse_rdap_domain(data)


async def rdap_ip(client, ip):
    _, data = await fetch_json(client, f"https://rdap.org/ip/{ip}")
    return parse_rdap_ip(data)


# --- DNS ---

DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]


def _rdata_text(rdtype, rdata):
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode(errors="replace")
    return rdata.to_text()


async def dns_records(domain, types=None, nameserver=None):
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    if nameserver:
        resolver.nameservers = [nameserver]

    records = {}
    for rdtype in types or DEFAULT_RECORD_TYPES:
        rdtype = rdtype.upper()
        try:
            answer = await resolver.resolve(domain, rdtype)
        except dns.resolver.NXDOMAIN:
            return {"domain": domain, "error": "NXDOMAIN (domain doesn't exist)"}
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            records[rdtype] = ["<timeout>"]
            continue
        records[rdtype] = sorted(_rdata_text(rdtype, r) for r in answer)
    return {"domain": domain, "records": records}


async def txt_records(name):
    """TXT strings for a name, [] if there are none or the name doesn't exist."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    return [_rdata_text("TXT", r) for r in answer]


async def reverse_dns(ip):
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
    except dns.exception.DNSException:
        return []
    return sorted(r.to_text().rstrip(".") for r in answer)


# --- certificate transparency (crt.sh) ---

def parse_crtsh(rows: list, domain: str) -> list[str]:
    names = set()
    for row in rows:
        for name in row.get("name_value", "").splitlines():
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


async def crtsh_subdomains(client, domain):
    # crt.sh can take a while on big domains
    _, rows = await fetch_json(
        client,
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        retries=2,
        timeout=60.0,
    )
    rows = rows or []
    return {"domain": domain, "certs_seen": len(rows), "subdomains": parse_crtsh(rows, domain)}


# --- wayback machine ---

def parse_cdx(rows: list) -> list[dict]:
    if not rows:
        return []
    header, *rest = rows
    out = []
    for row in rest:
        item = dict(zip(header, row))
        item["archive_url"] = f"https://web.archive.org/web/{item['timestamp']}/{item['original']}"
        out.append(item)
    return out


async def wayback_snapshots(client, url, limit=20, newest_first=True, year_from=None, year_to=None):
    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "digest",
        # negative limit = last N results
        "limit": -limit if newest_first else limit,
    }
    if year_from:
        params["from"] = str(year_from)
    if year_to:
        params["to"] = str(year_to)

    # the cdx api regularly takes 20-30s, give it room
    _, rows = await fetch_json(
        client, "https://web.archive.org/cdx/search/cdx", params=params, retries=2, timeout=60.0
    )
    snaps = parse_cdx(rows or [])
    if newest_first:
        snaps.reverse()
    return {"url": url, "count": len(snaps), "snapshots": snaps}


# --- http headers ---

async def http_headers(client, url):
    if "://" not in url:
        url = "https://" + url
    r = await client.get(url)
    headers = {k.lower(): v for k, v in r.headers.items()}
    return {
        "url": url,
        "final_url": str(r.url),
        "status": r.status_code,
        "redirects": [str(h.url) for h in r.history],
        "server": headers.get("server"),
        "headers": headers,
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in headers],
    }


# --- shodan internetdb (free, no key) ---

async def internetdb(client, ip):
    status, data = await fetch_json(client, f"https://internetdb.shodan.io/{ip}", ok=(200, 404))
    if status == 404:
        return {"ip": ip, "ports": [], "note": "shodan has nothing on this ip"}
    return data
