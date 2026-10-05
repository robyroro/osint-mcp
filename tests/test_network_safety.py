import asyncio
import gzip

import httpx
import pytest

from osint_mcp import network


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://10.1.2.3",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://224.0.0.1",
        "file:///etc/passwd",
        "ftp://example.com",
        "https://user:pass@example.com",
        "http://host.local",
        "http://foo.localhost",
        "http://localhost",
    ],
)
def test_reject_unsafe_urls(url):
    with pytest.raises(ValueError):
        network.normalize_url(url)


def test_idna_and_ipv6():
    assert network.normalize_url("https://münchen.de").raw_host == b"xn--mnchen-3ya.de"
    assert network.normalize_url("https://[2606:4700::1111]/").host == "2606:4700::1111"


def test_mixed_dns_answers_fail_closed(monkeypatch):
    async def lookup(*args, **kwargs):
        return [(2, 1, 6, "", ("1.1.1.1", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]

    async def scenario():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", lookup)
        with pytest.raises(ValueError, match="private"):
            await network.resolve_public("example.com", 443)

    asyncio.run(scenario())


def test_transport_pins_ip_preserves_host_and_sni(monkeypatch):
    calls = []

    async def resolve(host, port):
        return ["1.1.1.1"]

    def respond(request):
        calls.append(request)
        return httpx.Response(200, text="hello")

    monkeypatch.setattr(network, "resolve_public", resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(respond))

    async def scenario():
        async with httpx.AsyncClient(transport=network.PublicTransport()) as client:
            result = await client.get("https://example.com:8443/path")
            assert str(result.url) == "https://example.com:8443/path"

    asyncio.run(scenario())
    assert calls[0].url.host == "1.1.1.1"
    assert calls[0].headers["host"] == "example.com:8443"
    assert calls[0].extensions["sni_hostname"] == "example.com"


def test_redirect_to_private_ip_never_reaches_transport(monkeypatch):
    calls = []

    async def resolve(host, port):
        return ["1.1.1.1"]

    def respond(request):
        calls.append(request.url)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    monkeypatch.setattr(network, "resolve_public", resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(respond))

    async def scenario():
        async with httpx.AsyncClient(
            transport=network.PublicTransport(), follow_redirects=True
        ) as client:
            with pytest.raises(ValueError, match="private"):
                await client.get("https://example.com")

    asyncio.run(scenario())
    assert len(calls) == 1


def test_different_hostnames_use_separate_pools(monkeypatch):
    pools = []

    async def resolve(host, port):
        return ["1.1.1.1"]

    def transport(**kwargs):
        pools.append(1)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    monkeypatch.setattr(network, "resolve_public", resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", transport)

    async def scenario():
        async with httpx.AsyncClient(transport=network.PublicTransport()) as client:
            await client.get("https://first.com")
            await client.get("https://second.com")
            await client.get("https://first.com")

    asyncio.run(scenario())
    assert len(pools) == 2


def test_decoded_body_limit_and_normal_gzip():
    def handler(request):
        return httpx.Response(
            200, headers={"content-encoding": "gzip"}, content=gzip.compress(b"hello world")
        )

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await network.read_limited(client, "https://example.com", max_bytes=20)
            assert result.text == "hello world"
            with pytest.raises(ValueError, match="limit"):
                await network.read_limited(client, "https://example.com", max_bytes=5)

    asyncio.run(scenario())


def test_streamed_compression_bomb_is_stopped_before_full_inflation():
    class Compressed(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield gzip.compress(b"x" * 2_000_000)

    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Compressed())

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError, match="limit"):
                await network.read_limited(client, "https://example.com", max_bytes=1024)

    asyncio.run(scenario())


def test_redirect_body_has_a_decoded_limit_too(monkeypatch):
    class Compressed(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield gzip.compress(b"x" * 100_000)

    async def resolve(host, port):
        return ["1.1.1.1"]

    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(
            302, headers={"content-encoding": "gzip", "location": "/next"}, stream=Compressed()
        )

    monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 1024)
    monkeypatch.setattr(network, "resolve_public", resolve)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(handler))

    async def scenario():
        async with httpx.AsyncClient(
            transport=network.PublicTransport(), follow_redirects=True
        ) as client:
            with pytest.raises(ValueError, match="decoded response"):
                await client.get("https://example.com/")

    asyncio.run(scenario())
    assert len(calls) == 1
