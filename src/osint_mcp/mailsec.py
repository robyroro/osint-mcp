"""Email security posture: SPF, DMARC, MTA-STS, TLS-RPT, DKIM + a rough grade."""

import asyncio
import secrets

import httpx

from . import sources

# selectors used by the big providers, we can't list them so we just try these
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "mail", "dkim", "mandrill", "smtp", "zoho",
]


def parse_spf(txts):
    records = [t for t in txts if t.lower().startswith("v=spf1")]
    if not records:
        return {"present": False}
    if len(records) > 1:
        return {"present": True, "valid": False, "records": records}

    record = records[0]
    all_q = None
    redirect = None
    lookups = 0
    for term in record.split()[1:]:
        t = term.lower()
        qualifier = t[0] if t[0] in "+-~?" else "+"
        body = t.lstrip("+-~?")
        if body == "all":
            all_q = qualifier + "all"
        elif body.startswith("redirect="):
            redirect = body.split("=", 1)[1]
            lookups += 1
        elif body.startswith(("include:", "exists:")) or body.split(":")[0].split("/")[0] in ("a", "mx", "ptr"):
            lookups += 1

    return {
        "present": True,
        "valid": True,
        "record": record,
        "all": all_q,
        "redirect": redirect,
        # only counts this record, includes can add more on top
        "lookups": lookups,
    }


def parse_dmarc(txts):
    records = [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]
    if not records:
        return {"present": False}
    if len(records) > 1:
        return {"present": True, "valid": False, "records": records}

    tags = {}
    for part in records[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    try:
        pct = int(tags.get("pct", 100))
    except ValueError:
        pct = 100
    policy = tags.get("p", "").lower() or None
    return {
        "present": True,
        "valid": policy in ("none", "quarantine", "reject"),
        "record": records[0],
        "policy": policy,
        "subdomain_policy": tags.get("sp", "").lower() or policy,
        "pct": pct,
        "rua": [x.strip() for x in tags.get("rua", "").split(",") if x.strip()],
        "ruf": [x.strip() for x in tags.get("ruf", "").split(",") if x.strip()],
    }


def parse_mta_sts_policy(text):
    policy = {"mx": []}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        if k == "mx":
            policy["mx"].append(v)
        elif k in ("version", "mode", "max_age"):
            policy[k] = v
    return policy


def grade(spf, dmarc, mta_sts=None, has_mx=True):
    issues = []

    spf_ok = False
    if not spf["present"]:
        issues.append("no SPF record")
    elif not spf["valid"]:
        issues.append("more than one SPF record, receivers treat that as a permerror")
    else:
        if spf["all"] == "+all":
            issues.append("SPF ends in +all, which allows any server on the internet")
        elif spf["all"] in ("?all", None) and not spf["redirect"]:
            issues.append("SPF is neutral (?all or no 'all'), it doesn't block anything")
        else:
            spf_ok = True
        if spf["lookups"] > 10:
            issues.append(f"SPF needs {spf['lookups']} DNS lookups, the limit is 10")

    if not dmarc["present"]:
        issues.append("no DMARC record, spoofed mail won't be rejected and nobody gets reports")
    elif not dmarc["valid"]:
        issues.append("DMARC record is broken (duplicate or missing p=)")
    else:
        if dmarc["policy"] == "none":
            issues.append("DMARC is p=none, that's monitoring only")
        if dmarc["pct"] < 100:
            issues.append(f"DMARC only applies to {dmarc['pct']}% of mail")
        if not dmarc["rua"]:
            issues.append("DMARC has no rua=, no aggregate reports are being collected")

    if mta_sts is not None and mta_sts.get("mode") != "enforce":
        issues.append("no MTA-STS in enforce mode, inbound TLS can be downgraded")

    if not has_mx and not (spf.get("all") == "-all" and dmarc.get("policy") == "reject"):
        issues.append("domain has no MX. if it never sends mail it should publish "
                      "'v=spf1 -all' and a DMARC p=reject")

    if spf.get("all") == "+all":
        letter = "F"
    elif not dmarc.get("valid"):
        letter = "D" if spf_ok else "F"
    elif dmarc["policy"] == "reject" and dmarc["pct"] == 100:
        letter = "A" if spf_ok else "B"
    elif dmarc["policy"] in ("reject", "quarantine"):
        letter = "B"
    else:
        letter = "C"

    return letter, issues


async def _mta_sts(client, domain, txts):
    record = next((t for t in txts if t.lower().startswith("v=stsv1")), None)
    if record is None:
        return {"present": False}
    out = {"present": True, "record": record}
    try:
        r = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=10.0)
        r.raise_for_status()
        out.update(parse_mta_sts_policy(r.text))
    except httpx.HTTPError as e:
        out["policy_error"] = f"couldn't fetch the policy file: {e.__class__.__name__}"
    return out


def dkim_key(txts):
    """The p= value of a DKIM record, '' if revoked/empty, None if there's no key."""
    for t in txts:
        for part in t.split(";"):
            k, _, v = part.partition("=")
            if k.strip() == "p":
                return v.strip().replace(" ", "")
    return None


async def _dkim(domain, selectors):
    # some domains (example.com for one) answer every selector with a
    # wildcard record, so ask for a made up one first to know what that looks like
    probe = "osint-mcp-" + secrets.token_hex(4)
    answers = await asyncio.gather(
        *(sources.txt_records(f"{s}._domainkey.{domain}") for s in [probe, *selectors])
    )
    wildcard, answers = answers[0], answers[1:]

    found, revoked = [], []
    for sel, txts in zip(selectors, answers):
        if not txts or txts == wildcard:
            continue
        key = dkim_key(txts)
        if key:
            found.append(sel)
        elif key == "":
            revoked.append(sel)

    out = {"found": found, "revoked": revoked, "wildcard": wildcard[0] if wildcard else None}
    if wildcard and dkim_key(wildcard) == "":
        out["note"] = "every selector returns an empty key, i.e. the domain says it doesn't sign mail"
    else:
        out["note"] = "only common selectors were tried, not finding one doesn't mean there's no DKIM"
    return out


async def check(client, domain, dkim_selectors=None):
    selectors = dkim_selectors or COMMON_DKIM_SELECTORS
    root_txt, dmarc_txt, sts_txt, tlsrpt_txt, mx, dkim = await asyncio.gather(
        sources.txt_records(domain),
        sources.txt_records(f"_dmarc.{domain}"),
        sources.txt_records(f"_mta-sts.{domain}"),
        sources.txt_records(f"_smtp._tls.{domain}"),
        sources.dns_records(domain, ["MX"]),
        _dkim(domain, selectors),
    )
    spf = parse_spf(root_txt)
    dmarc = parse_dmarc(dmarc_txt)
    mta_sts = await _mta_sts(client, domain, sts_txt)
    mx_hosts = mx.get("records", {}).get("MX", [])
    letter, issues = grade(spf, dmarc, mta_sts, has_mx=bool(mx_hosts))

    return {
        "domain": domain,
        "grade": letter,
        "issues": issues,
        "mx": mx_hosts,
        "spf": spf,
        "dmarc": dmarc,
        "mta_sts": mta_sts,
        "tls_rpt": next((t for t in tlsrpt_txt if t.lower().startswith("v=tlsrptv1")), None),
        "dkim": dkim,
    }
