"""Small sqlite cache for API responses so we don't hammer crt.sh & co.

OSINT_MCP_CACHE=off        disable it
OSINT_MCP_CACHE_PATH=...   where the db lives (default ~/.cache/osint-mcp/cache.sqlite3)
OSINT_MCP_CACHE_TTL=21600  seconds, default 6h
"""

import json
import os
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlencode

DEFAULT_TTL = 6 * 3600


class Cache:
    def __init__(self, path, ttl=DEFAULT_TTL):
        self.ttl = ttl
        self.db = None
        if path is None:
            return
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute(
            "create table if not exists responses ("
            " key text primary key, status integer, body text, expires real)"
        )

    @staticmethod
    def key(url, params=None):
        if params:
            url += "?" + urlencode(sorted(params.items()))
        return url

    def get(self, key):
        if self.db is None:
            return None
        row = self.db.execute(
            "select status, body, expires from responses where key = ?", (key,)
        ).fetchone()
        if row is None or row[2] < time.time():
            return None
        return row[0], json.loads(row[1])

    def set(self, key, status, data, ttl=None):
        if self.db is None:
            return
        expires = time.time() + (ttl if ttl is not None else self.ttl)
        self.db.execute(
            "insert or replace into responses values (?, ?, ?, ?)",
            (key, status, json.dumps(data), expires),
        )
        self.db.commit()

    def clear(self):
        if self.db is not None:
            self.db.execute("delete from responses")
            self.db.commit()


_cache = None


def get_cache():
    global _cache
    if _cache is None:
        if os.environ.get("OSINT_MCP_CACHE", "").lower() in ("off", "0", "false", "no"):
            _cache = Cache(None)
        else:
            path = os.environ.get("OSINT_MCP_CACHE_PATH") or str(
                Path.home() / ".cache" / "osint-mcp" / "cache.sqlite3"
            )
            ttl = int(os.environ.get("OSINT_MCP_CACHE_TTL", DEFAULT_TTL))
            _cache = Cache(path, ttl)
    return _cache


def set_cache(cache):
    global _cache
    _cache = cache
