import asyncio
import ssl
import time
from datetime import datetime, timezone

OLD_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _name(rdns):
    # getpeercert() gives ((('commonName', 'x'),), (('organizationName', 'y'),))
    return {k: v for rdn in rdns for k, v in rdn}


def parse_cert(cert, now=None):
    now = now or time.time()
    subject = _name(cert.get("subject", ()))
    issuer = _name(cert.get("issuer", ()))
    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    return {
        "subject": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_before": _iso(not_before),
        "not_after": _iso(not_after),
        "days_left": int((not_after - now) // 86400),
        "sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        "serial": cert.get("serialNumber"),
    }


def warnings_for(info):
    out = []
    if info["days_left"] < 0:
        out.append("certificate is expired")
    elif info["days_left"] < 14:
        out.append(f"certificate expires in {info['days_left']} days")
    if info.get("tls_version") in OLD_PROTOCOLS:
        out.append(f"negotiated {info['tls_version']}, that's deprecated")
    return out


async def fetch_certificate(host, port=443, timeout=10.0):
    base = {"host": host, "port": port}
    ctx = ssl.create_default_context()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
        )
    except ssl.SSLCertVerificationError as e:
        return {**base, "valid": False, "error": e.verify_message or str(e)}
    except ssl.SSLError as e:
        return {**base, "valid": False, "error": f"tls handshake failed: {e.reason or e}"}
    except (OSError, asyncio.TimeoutError) as e:
        return {**base, "error": f"couldn't connect: {e.__class__.__name__}"}

    try:
        obj = writer.get_extra_info("ssl_object")
        info = {**base, "valid": True, **parse_cert(obj.getpeercert())}
        info["tls_version"] = obj.version()
        info["cipher"] = obj.cipher()[0]
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass

    info["warnings"] = warnings_for(info)
    return info
