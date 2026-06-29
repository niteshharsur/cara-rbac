"""
pod_matcher/cache.py

Response cache for M2 LLM results, keyed by image digest.
Avoids re-running the LLM (and paying API costs) for the same image
across multiple scans.

Storage: PostgreSQL table `pod_match_cache` with TTL.
Falls back to in-process dict cache if DB is unavailable.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

# Cache TTL: 7 days by default (images rarely change their entrypoint)
DEFAULT_TTL_SECONDS = int(os.getenv("POD_MATCH_CACHE_TTL", str(7 * 24 * 3600)))


class InMemoryCache:
    """Thread-unsafe in-process cache used as fallback when Postgres is unavailable."""

    def __init__(self, ttl: int = DEFAULT_TTL_SECONDS):
        self._store: dict[str, tuple[dict, float]] = {}
        self._ttl = ttl

    def get(self, key: str) -> Optional[dict]:
        if key not in self._store:
            return None
        value, ts = self._store[key]
        if time.time() - ts > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: dict) -> None:
        self._store[key] = (value, time.time())

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)


class PostgresCache:
    """
    Persistent cache backed by the `pod_match_cache` table.

    Schema (add to migration if not present):
    CREATE TABLE IF NOT EXISTS pod_match_cache (
        cache_key   TEXT PRIMARY KEY,
        result_json JSONB NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at  TIMESTAMPTZ NOT NULL
    );
    """

    def __init__(self, db_url: str, ttl: int = DEFAULT_TTL_SECONDS):
        import psycopg2
        self._conn = psycopg2.connect(db_url)
        self._conn.autocommit = True
        self._ttl = ttl
        self._ensure_table()

    def _ensure_table(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pod_match_cache (
                    cache_key   TEXT PRIMARY KEY,
                    result_json JSONB NOT NULL,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at  TIMESTAMPTZ NOT NULL
                )
            """)

    def get(self, key: str) -> Optional[dict]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT result_json FROM pod_match_cache "
                "WHERE cache_key = %s AND expires_at > now()",
                (key,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return row[0]

    def set(self, key: str, value: dict) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pod_match_cache (cache_key, result_json, expires_at)
                VALUES (%s, %s, now() + interval '%s seconds')
                ON CONFLICT (cache_key) DO UPDATE
                  SET result_json = EXCLUDED.result_json,
                      created_at  = now(),
                      expires_at  = EXCLUDED.expires_at
                """,
                (key, json.dumps(value), self._ttl),
            )

    def invalidate(self, key: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM pod_match_cache WHERE cache_key = %s", (key,))


def make_cache_key(image_ref: str, image_digest: str) -> str:
    """
    Stable cache key: SHA-256 of (image_ref + digest).
    digest alone is sufficient, but including image_ref makes debugging easier.
    """
    raw = f"{image_ref}::{image_digest}"
    return hashlib.sha256(raw.encode()).hexdigest()


def build_cache(db_url: Optional[str] = None) -> InMemoryCache | PostgresCache:
    """Factory: returns a Postgres cache if db_url is available, else in-memory."""
    if db_url:
        try:
            return PostgresCache(db_url)
        except Exception as exc:
            log.warning("postgres_cache_unavailable", error=str(exc), fallback="in-memory")
    return InMemoryCache()
