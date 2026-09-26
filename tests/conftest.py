import pytest

from osint_mcp import cache


@pytest.fixture(autouse=True)
def no_cache():
    # every test starts with the cache off, tests that care turn it on
    cache.set_cache(cache.Cache(None))
    yield
    cache.set_cache(None)
