from __future__ import annotations
import os
import sqlite3
import datetime as dt
from contextlib import contextmanager
from .config import DB_PATH, HUB_HOSTS


def utcnow() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS hosts (
                host TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'active',
                verified_hits_total INTEGER NOT NULL DEFAULT 0,
                last_bot_hit_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS digests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                topic TEXT NOT NULL,
                shard INTEGER NOT NULL DEFAULT 0,
                url_count INTEGER NOT NULL DEFAULT 0,
                websub_status INTEGER,
                websub_pinged_at TEXT,
                hub_crawled_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_digests_host ON digests(host, id DESC);
            CREATE INDEX IF NOT EXISTS idx_digests_shard ON digests(host, shard, id DESC);

            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                is_pdf INTEGER NOT NULL DEFAULT 0,
                topic TEXT NOT NULL DEFAULT 'general',
                title TEXT,
                description TEXT,
                host TEXT,
                shard INTEGER NOT NULL DEFAULT 0,
                digest_id INTEGER,
                status TEXT NOT NULL DEFAULT 'queued',
                http_status INTEGER,
                error TEXT,
                websub_status INTEGER,
                websub_pinged_at TEXT,
                hub_crawled_at TEXT,
                target_crawled_at TEXT,
                telegraph_url TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_urls_status ON urls(status);
            CREATE INDEX IF NOT EXISTS idx_urls_digest ON urls(digest_id);
            CREATE INDEX IF NOT EXISTS idx_urls_url ON urls(url);

            CREATE TABLE IF NOT EXISTS bot_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                host TEXT,
                path TEXT NOT NULL,
                ua TEXT NOT NULL,
                bot_family TEXT NOT NULL,
                verdict TEXT NOT NULL,
                rdns TEXT,
                fcrdns_ok INTEGER NOT NULL DEFAULT 0,
                range_list TEXT,
                digest_id INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_bot_hits_ts ON bot_hits(ts DESC);

            CREATE TABLE IF NOT EXISTS freshness_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                link TEXT NOT NULL UNIQUE,
                summary TEXT,
                published_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rss_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                feed_url TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_fetched_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            """
        )
        now = utcnow()
        for h in HUB_HOSTS:
            conn.execute("INSERT OR IGNORE INTO hosts (host, state, created_at) VALUES (?, 'active', ?)", (h, now))
        defaults = [
            ("Hacker News", "https://hnrss.org/newest?count=10"),
            ("USGS Earthquakes", "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.atom"),
        ]
        for name, furl in defaults:
            conn.execute("INSERT OR IGNORE INTO rss_sources (name, feed_url, enabled, created_at) VALUES (?,?,1,?)", (name, furl, now))


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def pick_active_host() -> str:
    """Round-robin across active hosts, preferring hosts with verified Googlebot hits."""
    with get_conn() as c:
        rows = c.execute(
            "SELECT host, verified_hits_total FROM hosts WHERE state='active' ORDER BY verified_hits_total DESC, host ASC"
        ).fetchall()
        if rows:
            idx = c.execute("SELECT COUNT(*) FROM digests").fetchone()[0] % len(rows)
            return rows[idx]["host"]
        any_row = c.execute("SELECT host FROM hosts ORDER BY created_at ASC LIMIT 1").fetchone()
        return any_row["host"] if any_row else HUB_HOSTS[0]


def kv_get(key: str) -> str | None:
    with get_conn() as c:
        row = c.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return row["v"] if row else None


def kv_set(key: str, val: str):
    with get_conn() as c:
        c.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (key, val))
