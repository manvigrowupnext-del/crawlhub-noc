"""
Background async workers:
  1. Concurrent pre-flight validator (SSRF-safe, HTTP 200, noindex, title/desc/PDF, auto-topic)
  2. 50-URL Batched Topic Digest Builder -> assigns batches to active hosts & shards
  3. Batched WebSub (PubSubHubbub) publisher -> https://pubsubhubbub.appspot.com/
  4. Optional Telegraph (telegra.ph) curated digest publisher (disabled by default for high volume)
  5. Optional public freshness warm-up feed (Hacker News RSS + USGS Earthquakes)
"""
from __future__ import annotations
import asyncio
import datetime as dt
import html
import ipaddress
import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
import httpx

from .config import (
    BASE_DOMAIN,
    DIGEST_BATCH_SIZE,
    DIGEST_FLUSH_SECONDS,
    ENABLE_FRESHNESS,
    FRESHNESS_INTERVAL_MIN,
    PREFLIGHT_CONCURRENCY,
    PREFLIGHT_PROXY_URL,
    PREFLIGHT_TIMEOUT,
    SHARD_COUNT,
    SITE_NAME,
    TELEGRAPH_DIGEST_EVERY,
    WEBSUB_BATCH_SECONDS,
    WEBSUB_HUB_URL,
    public_base_url,
)
from .db import get_conn, kv_get, kv_set, pick_active_host, utcnow
from .events import bus
from .verifier import verifier

# Track dirty (host, shard) pairs needing a WebSub ping
dirty_feeds: set[tuple[str, int]] = set()

TOPIC_RULES = [
    ("tech", re.compile(r"\b(api|code|cloud|software|linux|python|ai|dev|github|cyber|server|app)\b", re.I)),
    ("business", re.compile(r"\b(finance|market|stock|crypto|saas|pricing|startup|invest|tax|shop|store|product)\b", re.I)),
    ("news", re.compile(r"\b(news|report|update|202\d|breaking|guide|review|announce)\b", re.I)),
]


def classify_topic(url: str, title: str, is_pdf: bool) -> str:
    if is_pdf:
        return "docs-pdf"
    blob = f"{url} {title}"
    for name, rx in TOPIC_RULES:
        if rx.search(blob):
            return name
    return "general"


def is_safe_public_url(url: str) -> tuple[bool, str]:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False, "invalid_scheme_or_host"
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except Exception:
        return False, "dns_resolution_failed"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, "blocked_private_ip"
    return True, "ok"


async def preflight_url(url: str) -> dict:
    ok, reason = await asyncio.to_thread(is_safe_public_url, url)
    if not ok:
        return {"ok": False, "error": reason, "http_status": None}

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CrawlHubPreflight/1.0; +https://" + BASE_DOMAIN + ")",
        "Accept": "text/html,application/xhtml+xml,application/pdf,*/*;q=0.8",
    }
    client_kw = {"timeout": PREFLIGHT_TIMEOUT, "follow_redirects": True, "max_redirects": 5}
    if PREFLIGHT_PROXY_URL:
        client_kw["proxy"] = PREFLIGHT_PROXY_URL
    try:
        async with httpx.AsyncClient(**client_kw) as client:
            r = await client.get(url, headers=headers)
    except Exception as e:
        return {"ok": False, "error": f"fetch_error:{type(e).__name__}", "http_status": None}

    if r.status_code != 200:
        return {"ok": False, "error": f"http_{r.status_code}", "http_status": r.status_code}

    if "noindex" in (r.headers.get("x-robots-tag") or "").lower():
        return {"ok": False, "error": "x_robots_noindex", "http_status": r.status_code}

    ct = (r.headers.get("content-type") or "").lower()
    is_pdf = ("application/pdf" in ct) or urlsplit(url).path.lower().endswith(".pdf") or r.content[:5] == b"%PDF-"
    if is_pdf:
        fname = urlsplit(url).path.rsplit("/", 1)[-1] or "document.pdf"
        size_kb = max(1, len(r.content) // 1024)
        return {
            "ok": True,
            "http_status": r.status_code,
            "is_pdf": True,
            "topic": "docs-pdf",
            "title": f"{fname} (PDF Document)",
            "description": f"PDF document hosted on {urlsplit(url).hostname} ({size_kb} KB).",
        }

    text = r.text[:120_000]
    if re.search(r'<meta[^>]+name=["\']robots["\'][^>]+content=["\'][^"\']*noindex', text, re.I):
        return {"ok": False, "error": "meta_noindex", "http_status": r.status_code}

    m_title = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    title = re.sub(r"\s+", " ", html.unescape(m_title.group(1))).strip()[:180] if m_title else url
    m_desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', text, re.I)
    desc = re.sub(r"\s+", " ", html.unescape(m_desc.group(1))).strip()[:260] if m_desc else f"Web resource on {urlsplit(url).hostname}"
    return {
        "ok": True,
        "http_status": r.status_code,
        "is_pdf": False,
        "topic": classify_topic(url, title, False),
        "title": title,
        "description": desc,
    }


async def process_preflight_queue():
    sem = asyncio.Semaphore(PREFLIGHT_CONCURRENCY)

    async def handle_one(row):
        async with sem:
            res = await preflight_url(row["url"])
        now = utcnow()
        with get_conn() as c:
            if res["ok"]:
                c.execute(
                    """UPDATE urls SET status='ready', http_status=?, is_pdf=?, topic=?, title=?, description=?, updated_at=?
                       WHERE id=?""",
                    (res["http_status"], int(res["is_pdf"]), res["topic"], res["title"], res["description"], now, row["id"]),
                )
            else:
                c.execute(
                    "UPDATE urls SET status='preflight_failed', http_status=?, error=?, updated_at=? WHERE id=?",
                    (res.get("http_status"), res.get("error"), now, row["id"]),
                )

    while True:
        with get_conn() as c:
            rows = c.execute("SELECT id, url FROM urls WHERE status='queued' ORDER BY id ASC LIMIT ?", (PREFLIGHT_CONCURRENCY * 2,)).fetchall()
        if rows:
            await asyncio.gather(*(handle_one(r) for r in rows))
        else:
            await asyncio.sleep(2)


async def digest_batcher_loop():
    """Groups every DIGEST_BATCH_SIZE ready URLs (or flushes stale ones) into a single /digest/{id} page."""
    while True:
        await asyncio.sleep(5)
        now_dt = dt.datetime.utcnow()
        with get_conn() as c:
            topics = [r[0] for r in c.execute("SELECT DISTINCT topic FROM urls WHERE status='ready'").fetchall()]
            for topic in topics:
                rows = c.execute(
                    "SELECT id, created_at FROM urls WHERE status='ready' AND topic=? ORDER BY id ASC LIMIT ?",
                    (topic, DIGEST_BATCH_SIZE),
                ).fetchall()
                if not rows:
                    continue
                oldest = dt.datetime.fromisoformat(rows[0]["created_at"].replace("Z", ""))
                age_s = (now_dt - oldest).total_seconds()
                if len(rows) < DIGEST_BATCH_SIZE and age_s < DIGEST_FLUSH_SECONDS:
                    continue
                host = pick_active_host()
                now = utcnow()
                cur = c.execute(
                    "INSERT INTO digests (host, topic, shard, url_count, created_at) VALUES (?,?,?,?,?)",
                    (host, topic, 0, len(rows), now),
                )
                digest_id = cur.lastrowid
                shard = digest_id % SHARD_COUNT
                c.execute("UPDATE digests SET shard=? WHERE id=?", (shard, digest_id))
                ids = [r["id"] for r in rows]
                c.executemany(
                    "UPDATE urls SET status='published', host=?, shard=?, digest_id=?, updated_at=? WHERE id=?",
                    [(host, shard, digest_id, now, i) for i in ids],
                )
                dirty_feeds.add((host, shard))
                bus.publish("digest_created", {"digest_id": digest_id, "host": host, "topic": topic, "shard": shard, "url_count": len(rows), "ts": now})


async def websub_publisher_loop():
    while True:
        await asyncio.sleep(WEBSUB_BATCH_SECONDS)
        if not dirty_feeds:
            continue
        batch = list(dirty_feeds)
        dirty_feeds.clear()
        async with httpx.AsyncClient(timeout=15) as client:
            for host, shard in batch:
                base = public_base_url(host)
                if base.startswith("http://localhost") or base.startswith("http://127.0.0.1"):
                    continue
                feed_url = f"{base}/feeds/shard-{shard:02d}.atom"
                try:
                    r = await client.post(
                        WEBSUB_HUB_URL,
                        data={"hub.mode": "publish", "hub.url": feed_url},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    now = utcnow()
                    with get_conn() as c:
                        c.execute(
                            "UPDATE digests SET websub_status=?, websub_pinged_at=? WHERE host=? AND shard=? AND websub_pinged_at IS NULL",
                            (r.status_code, now, host, shard),
                        )
                        c.execute(
                            """UPDATE urls SET status=CASE WHEN status='published' THEN 'websub_pinged' ELSE status END,
                               websub_status=?, websub_pinged_at=?, updated_at=?
                               WHERE host=? AND shard=? AND websub_pinged_at IS NULL AND status IN ('published','websub_pinged')""",
                            (r.status_code, now, now, host, shard),
                        )
                    bus.publish("websub_ping", {"host": host, "shard": shard, "feed_url": feed_url, "status": r.status_code, "ts": now})
                except Exception:
                    dirty_feeds.add((host, shard))
                bus.publish("digest_created", {"digest_id": digest_id, "host": host, "topic": topic, "shard": shard, "url_count": len(rows), "ts": now})


async def ensure_telegraph_token() -> str | None:
    tok = kv_get("telegraph_access_token")
    if tok:
        return tok
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post("https://api.telegra.ph/createAccount", data={"short_name": "CrawlHub", "author_name": SITE_NAME[:60]})
            data = r.json()
            if data.get("ok"):
                tok = data["result"]["access_token"]
                kv_set("telegraph_access_token", tok)
                return tok
    except Exception:
        return None
    return None


async def telegraph_digest_loop():
    if TELEGRAPH_DIGEST_EVERY <= 0:
        return
    while True:
        await asyncio.sleep(60)
        base = public_base_url()
        if base.startswith("http://localhost") or base.startswith("http://127.0.0.1"):
            continue
        with get_conn() as c:
            rows = c.execute(
                """SELECT id, url, title, description FROM urls
                   WHERE status IN ('published','websub_pinged','bot_verified') AND telegraph_url IS NULL
                   ORDER BY id ASC LIMIT ?""",
                (TELEGRAPH_DIGEST_EVERY,),
            ).fetchall()
        if len(rows) < TELEGRAPH_DIGEST_EVERY:
            continue
        tok = await ensure_telegraph_token()
        if not tok:
            continue
        nodes = [{"tag": "p", "children": [f"Curated digest from {SITE_NAME} ({utcnow()})."]}]
        for r in rows:
            nodes.append({"tag": "p", "children": [{"tag": "a", "attrs": {"href": r["url"]}, "children": [r["title"] or r["url"]]}]})
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.telegra.ph/createPage",
                    json={"access_token": tok, "title": f"{SITE_NAME} Digest #{rows[-1]['id']}", "author_name": SITE_NAME[:60], "content": nodes},
                )
                data = resp.json()
                if data.get("ok"):
                    turl = data["result"]["url"]
                    with get_conn() as c:
                        c.executemany("UPDATE urls SET telegraph_url=?, updated_at=? WHERE id=?", [(turl, utcnow(), r["id"]) for r in rows])
        except Exception:
            pass


async def freshness_warmup_loop():
    if not ENABLE_FRESHNESS:
        return
    while True:
        with get_conn() as c:
            feeds = [(r["id"], r["name"], r["feed_url"]) for r in c.execute("SELECT id, name, feed_url FROM rss_sources WHERE enabled=1").fetchall()]
        async with httpx.AsyncClient(timeout=15) as client:
            for fid, source, url in feeds:
                try:
                    r = await client.get(url)
                    if r.status_code != 200:
                        continue
                    root = ET.fromstring(r.text)
                    items = []
                    for item in root.findall(".//item")[:8]:
                        t, l = (item.findtext("title") or "").strip(), (item.findtext("link") or "").strip()
                        if t and l:
                            items.append((source, t[:200], l, "", utcnow()))
                    ns = {"a": "http://www.w3.org/2005/Atom"}
                    for entry in root.findall(".//a:entry", ns)[:8]:
                        t = (entry.findtext("a:title", "", ns) or "").strip()
                        lk = entry.find("a:link", ns)
                        l = (lk.attrib.get("href") if lk is not None else "").strip()
                        if t and l:
                            items.append((source, t[:200], l, "", utcnow()))
                    with get_conn() as c:
                        c.executemany(
                            "INSERT OR IGNORE INTO freshness_items (source, title, link, summary, published_at) VALUES (?,?,?,?,?)",
                            items,
                        )
                        c.execute("UPDATE rss_sources SET last_fetched_at=? WHERE id=?", (utcnow(), fid))
                except Exception:
                    pass
        await asyncio.sleep(FRESHNESS_INTERVAL_MIN * 60)


async def ip_range_refresh_loop():
    while True:
        await verifier.refresh_ranges()
        await asyncio.sleep(3600)
