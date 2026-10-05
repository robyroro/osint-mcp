import asyncio
import ipaddress
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename
import httpx

from . import evidence, network
from .cache import get_cache

USER_AGENT = "osint-mcp/0.3 (+https://github.com/robyroro/osint-mcp)"

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
        max_redirects=5,
        transport=network.PublicTransport(),
        trust_env=False,
    )


async def get_flaky(client, url, retries=2, **kwargs):
    # crt.sh and archive.org both hand out 502/503s under load,
    # a retry or two usually gets through
    for attempt in range(retries + 1):
        r = await network.read_limited(client, url, **kwargs)
        if r.status_code not in (502, 503, 504) or attempt == retries:
            return r
        await asyncio.sleep(2 * (attempt + 1))


def describe_error(exc):
    """Short human readable version of whatever went wrong talking to an API."""
    try:
        host = exc.request.url.host
    except (AttributeError, RuntimeError):
        host = "the server"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"{host} returned {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return f"timed out talking to {host}, try again"
    if isinstance(exc, httpx.RequestError):
        return f"request to {host} failed: {exc.__class__.__name__}"
    return f"{exc.__class__.__name__}: {exc}"


async def fetch_json(client, url, params=None, retries=0, ok=(200,), **kwargs):
    """GET + json with the sqlite cache in front. Returns (status, data).
    Statuses outside `ok` raise, same as raise_for_status()."""
    cache = get_cache()
    key = cache.key(url, params)
    hit = cache.get_entry(key)
    if hit is not None:
        def iso(timestamp):
            return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='seconds') if timestamp is not None else None
        evidence.record('HTTP API', key, status=str(hit[0]), cached=True,
                        fetched_at=iso(hit[2]), expires_at=iso(hit[3]))
        return hit[:2]

    try:
        r = await get_flaky(client, url, retries=retries, params=params, **kwargs)
    except (httpx.HTTPError, ValueError) as error:
        evidence.record('HTTP API', key, status='error', error=describe_error(error))
        raise
    evidence.record('HTTP API', str(r.url), status=str(r.status_code), fetched_at=evidence.now())
    if r.status_code not in ok:
        r.raise_for_status()
    data = r.json() if r.content else None
    cache.set(key, r.status_code, data)
    return r.status_code, data


def clean_domain(value: str) -> str:
    """Accepts 'example.com', 'https://Example.com/x', 'www.example.com.' etc."""
    return network.hostname(network.normalize_url(value.strip()).host)


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
        resolver.nameservers = [network.public_ip(nameserver)]

    records = {}
    selected = types or DEFAULT_RECORD_TYPES
    if len(selected) > 16:
        raise ValueError('at most 16 DNS record types can be requested')
    for rdtype in selected:
        rdtype = rdtype.upper()
        try:
            answer = await resolver.resolve(domain, rdtype)
        except dns.resolver.NXDOMAIN:
            evidence.record('DNS', f'dns://{domain}', status='nxdomain', fetched_at=evidence.now())
            return {"domain": domain, "error": "NXDOMAIN (domain doesn't exist)"}
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            records[rdtype] = ['<unavailable>']
            continue
        except dns.exception.Timeout:
            records[rdtype] = ["<timeout>"]
            continue
        records[rdtype] = sorted(_rdata_text(rdtype, r) for r in answer)
    partial = any(any(value.startswith('<') for value in values) for values in records.values())
    evidence.record('DNS', f'dns://{domain}', status='partial' if partial else 'ok', fetched_at=evidence.now(),
                    resolver=nameserver or 'system', record_types=selected)
    return {"domain": domain, "records": records}


async def txt_records(name):
    """TXT strings for a name, [] if there are none or the name doesn't exist."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        evidence.record('DNS TXT', f'dns://{name}', status='no_records', fetched_at=evidence.now())
        return []
    except dns.exception.DNSException as error:
        evidence.record('DNS TXT', f'dns://{name}', status='error', error=error.__class__.__name__)
        raise ValueError(f'could not read TXT records for {name}: {error.__class__.__name__}') from error
    evidence.record('DNS TXT', f'dns://{name}', fetched_at=evidence.now(), resolver='system')
    return [_rdata_text("TXT", r) for r in answer]


async def reverse_dns(ip):
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
    except dns.exception.DNSException:
        evidence.record('DNS PTR', f'dns://{dns.reversename.from_address(ip)}', status='no_response')
        return []
    evidence.record('DNS PTR', f'dns://{dns.reversename.from_address(ip)}', fetched_at=evidence.now())
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
    url = str(network.normalize_url(url))
    async with client.stream('GET', url) as r:
        headers = {k.lower(): v for k, v in r.headers.items()}
        evidence.record('Website HTTP', str(r.url), status=str(r.status_code), fetched_at=evidence.now())
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


# --- ASN / BGP (RIPEstat, free, works for every RIR not just RIPE) ---

RIPESTAT = "https://stat.ripe.net/data/"


def parse_asn_query(value):
    """'1.1.1.1' -> ('ip', '1.1.1.1'), 'AS13335' / '13335' -> ('asn', 13335)"""
    value = value.strip()
    try:
        return "ip", clean_ip(value)
    except ValueError:
        pass
    num = value.upper().removeprefix("AS")
    if not num.isdigit():
        raise ValueError(f"expected an ip or an AS number, got {value!r}")
    return "asn", int(num)


async def _ripestat(client, endpoint, resource):
    _, body = await fetch_json(
        client, RIPESTAT + endpoint + "/data.json",
        params={"resource": resource, "sourceapp": "osint-mcp"},
    )
    return (body or {}).get("data", {})


async def asn_info(client, query, include_prefixes=True, max_prefixes=100):
    kind, value = parse_asn_query(query)
    out = {}
    if kind == "ip":
        net = await _ripestat(client, "network-info", value)
        asns = net.get("asns", [])
        out.update(ip=value, prefix=net.get("prefix"))
        if not asns:
            out["error"] = "this ip isn't announced by any AS right now"
            return out
        if len(asns) > 1:
            out["all_asns"] = [int(a) for a in asns]
        asn = int(asns[0])
    else:
        asn = value

    overview = await _ripestat(client, "as-overview", f"AS{asn}")
    out.update(asn=asn, holder=overview.get("holder"), announced=overview.get("announced"))

    if include_prefixes:
        announced = await _ripestat(client, "announced-prefixes", f"AS{asn}")
        prefixes = [p["prefix"] for p in announced.get("prefixes", [])]
        def by_net(prefix):
            return ipaddress.ip_network(prefix, strict=False)
        v4 = sorted((p for p in prefixes if ":" not in p), key=by_net)
        v6 = sorted((p for p in prefixes if ":" in p), key=by_net)
        out["prefix_count"] = {"ipv4": len(v4), "ipv6": len(v6)}
        out["prefixes"] = (v4 + v6)[:max_prefixes]
        if len(prefixes) > max_prefixes:
            out["prefixes_truncated"] = True
    return out
