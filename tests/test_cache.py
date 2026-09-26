import asyncio

import httpx

from osint_mcp import cache, sources


def test_roundtrip_and_expiry():
    c = cache.Cache(":memory:", ttl=60)
    c.set("k", 200, {"a": 1})
    assert c.get("k") == (200, {"a": 1})

    c.set("old", 200, [1], ttl=-1)
    assert c.get("old") is None
    assert c.get("missing") is None


def test_disabled_cache_is_a_noop():
    c = cache.Cache(None)
    c.set("k", 200, {"a": 1})
    assert c.get("k") is None


def test_key_ignores_param_order():
    assert cache.Cache.key("u", {"b": 2, "a": 1}) == cache.Cache.key("u", {"a": 1, "b": 2})


def test_fetch_json_only_hits_network_once():
    cache.set_cache(cache.Cache(":memory:"))
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, json={"ip": "1.2.3.4", "ports": [22]})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            first = await sources.internetdb(c, "1.2.3.4")
            second = await sources.internetdb(c, "1.2.3.4")
            return first, second

    first, second = asyncio.run(go())
    assert first == second == {"ip": "1.2.3.4", "ports": [22]}
    assert len(calls) == 1


def test_404s_are_cached_too():
    cache.set_cache(cache.Cache(":memory:"))
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(404)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            await sources.rdap_domain(c, "emag.ro")
            return await sources.rdap_domain(c, "emag.ro")

    assert "error" in asyncio.run(go())
    assert len(calls) == 1
