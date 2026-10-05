"""Public network requests, with DNS pinned before opening a connection."""

import asyncio
import ipaddress
import re
import socket
import zlib

import httpx

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def hostname(value):
    value = value.rstrip(".").lower()
    if "%" in value:
        raise ValueError("IPv6 scope IDs are not supported")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("invalid hostname") from error
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise ValueError("expected a domain name or IP address")
    if value.endswith((".localhost", ".local", ".internal", ".home.arpa")):
        raise ValueError("local hostnames are not supported")
    return value


def public_ip(value):
    address = ipaddress.ip_address(value)
    mapped = isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
    if not address.is_global or address.is_multicast or mapped:
        raise ValueError("private, local and reserved addresses are not supported")
    return str(address)


def normalize_url(value):
    if len(value) > 4096:
        raise ValueError("URL is too long (maximum 4096 characters)")
    if "://" not in value:
        value = "https://" + value.strip()
    try:
        url = httpx.URL(value)
        if url.scheme not in ("http", "https") or not url.host:
            raise ValueError("only http and https URLs are supported")
        if url.userinfo:
            raise ValueError("URLs with credentials are not supported")
        host = hostname(url.host)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            public_ip(host)
        return url.copy_with(host=host, fragment=None)
    except httpx.InvalidURL as error:
        raise ValueError("invalid URL") from error


async def resolve_public(host, port):
    host = hostname(host)
    try:
        return [public_ip(host)]
    except ValueError:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise
    records = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
        timeout=5.0,
    )
    addresses = list(dict.fromkeys(public_ip(record[4][0]) for record in records))
    if not addresses:
        raise ValueError("hostname has no public addresses")
    # IPv4 first so hosts with unusable local IPv6 routing still work.
    return sorted(addresses, key=lambda address: ":" in address)


class LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream, encoding=""):
        self.stream = stream
        encoding = encoding.strip().lower()
        self.decoder = None
        if encoding in ("gzip", "deflate"):
            self.decoder = zlib.decompressobj(
                16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
            )
        elif encoding not in ("", "identity"):
            raise ValueError(f"unsupported content encoding: {encoding}")

    async def __aiter__(self):
        total = 0
        decoded = 0
        async for chunk in self.stream:
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError("response exceeded the 8 MiB limit")
            if self.decoder is not None:
                try:
                    decoded += len(self.decoder.decompress(chunk, MAX_RESPONSE_BYTES - decoded + 1))
                except zlib.error as error:
                    raise ValueError("invalid compressed response") from error
                if decoded > MAX_RESPONSE_BYTES:
                    raise ValueError("decoded response exceeded the 8 MiB limit")
            yield chunk
        if self.decoder is not None and (not self.decoder.eof or self.decoder.unused_data):
            raise ValueError("incomplete or concatenated compressed response")

    async def aclose(self):
        await self.stream.aclose()


class PublicTransport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.transports = {}

    async def handle_async_request(self, request):
        url = normalize_url(str(request.url))
        port = url.port or (443 if url.scheme == "https" else 80)
        host = url.raw_host.decode("ascii")
        try:
            addresses = await resolve_public(host, port)
        except (OSError, asyncio.TimeoutError) as error:
            raise httpx.ConnectError("could not resolve the hostname", request=request) from error
        last_error = None
        for address in addresses:
            key = (host, port, address, url.scheme)
            if key not in self.transports:
                if len(self.transports) >= 128:
                    raise ValueError("too many different hosts in one request session")
                # Separate pools preserve SNI when different sites share an IP.
                self.transports[key] = httpx.AsyncHTTPTransport(
                    limits=httpx.Limits(max_connections=4, max_keepalive_connections=2)
                )
            headers = request.headers.copy()
            headers["Host"] = url.netloc.decode("ascii")
            headers["Accept-Encoding"] = "identity"
            pinned = httpx.Request(
                request.method,
                url.copy_with(host=address),
                headers=headers,
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": host},
            )
            try:
                response = await self.transports[key].handle_async_request(pinned)
                try:
                    stream = LimitedStream(
                        response.stream, response.headers.get("content-encoding", "")
                    )
                except ValueError:
                    await response.aclose()
                    raise
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    stream=stream,
                    extensions={**response.extensions, "peer_ip": address},
                    request=request,
                )
            except (httpx.ConnectError, httpx.ConnectTimeout) as error:
                last_error = error
        raise last_error

    async def aclose(self):
        await asyncio.gather(*(transport.aclose() for transport in self.transports.values()))


async def read_limited(client, url, max_bytes=MAX_RESPONSE_BYTES, **kwargs):
    """Read a bounded, decoded response; compressed bodies have the same limit."""
    request_headers = httpx.Headers(kwargs.pop("headers", None))
    request_headers["Accept-Encoding"] = "identity"
    async with client.stream("GET", url, headers=request_headers, **kwargs) as response:
        data = bytearray()
        encoding = response.headers.get("content-encoding", "").strip().lower()
        decoder = None
        if not response.is_stream_consumed:
            if encoding in ("gzip", "deflate"):
                decoder = zlib.decompressobj(
                    16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
                )
            elif encoding not in ("", "identity"):
                raise ValueError(f"unsupported content encoding: {encoding}")
        chunks = response.aiter_bytes() if response.is_stream_consumed else response.aiter_raw()
        async for chunk in chunks:
            if decoder is not None:
                try:
                    chunk = decoder.decompress(chunk, max_bytes - len(data) + 1)
                except zlib.error as error:
                    raise ValueError("invalid compressed response") from error
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ValueError(f"response exceeded the {max_bytes} byte limit")
        if decoder is not None and (not decoder.eof or decoder.unused_data):
            raise ValueError("incomplete or concatenated compressed response")
        headers = response.headers.copy()
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        result = httpx.Response(
            response.status_code,
            headers=headers,
            content=bytes(data),
            request=response.request,
            extensions=response.extensions,
        )
        result.history = response.history
        return result
