from __future__ import annotations
import asyncio
import hashlib
import html
import json
import os
import re
from typing import Optional
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as xml_escape

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from .config import (
    ADMIN_API_KEY,
    BASE_DOMAIN,
    SHARD_COUNT,
    SITE_NAME,
    TRUST_CF_IP,
    WEBSUB_HUB_URL,
    public_base_url,
)
from .db import get_conn, init_db, utcnow
from .events import bus
from .verifier import verifier
from .workers import (
    classify_topic,
    digest_batcher_loop,
    freshness_warmup_loop,
    ip_range_refresh_loop,
    process_preflight_queue,
    telegraph_digest_loop,
    websub_publisher_loop,
)

DIGEST_PATH_RE = re.compile(r"^/digest/(\d+)$")
SHARD_PATH_RE = re.compile(r"^/feeds/shard-(\d+)\.atom$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    tasks = [
        asyncio.create_task(ip_range_refresh_loop()),
        asyncio.create_task(process_preflight_queue()),
        asyncio.create_task(digest_batcher_loop()),
        asyncio.create_task(websub_publisher_loop()),
        asyncio.create_task(telegraph_digest_loop()),
        asyncio.create_task(freshness_warmup_loop()),
    ]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title=SITE_NAME, lifespan=lifespan)


def effective_host(request: Request) -> str:
    return (request.headers.get("x-forwarded-host") or request.headers.get("host") or BASE_DOMAIN).split(":")[0].lower()


def client_ip(request: Request) -> str:
    if TRUST_CF_IP:
        cf = request.headers.get("cf-connecting-ip")
        if cf:
            return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def require_api_key(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    token = x_api_key
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token or token != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


@app.middleware("http")
async def bot_verification_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith(("/api/", "/admin", "/favicon.ico")):
        return response
    ip = client_ip(request)
    ua = request.headers.get("user-agent", "")
    info = await verifier.verify(ip, ua)
    if info.get("is_bot"):
        host = effective_host(request)
        m = DIGEST_PATH_RE.match(path)
        digest_id = int(m.group(1)) if m else None
        now = utcnow()
        with get_conn() as c:
            c.execute(
                """INSERT INTO bot_hits (ts, ip, host, path, ua, bot_family, verdict, rdns, fcrdns_ok, range_list, digest_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (now, ip, host, path, ua[:300], info["bot_family"], info["verdict"], info["rdns"],
                 int(bool(info["fcrdns_ok"])), info["range_list"], digest_id),
            )
            bus.publish("bot_hit", {
                "ts": now, "ip": ip, "host": host, "path": path,
                "bot_family": info["bot_family"], "verdict": info["verdict"], "rdns": info["rdns"],
            })
            if info["verdict"] == "VERIFIED_BOT":
                is_search_bot = info["bot_family"] in ("googlebot-2.1", "google-inspectiontool", "bingbot", "yandexbot")
                c.execute(
                    "UPDATE hosts SET verified_hits_total=verified_hits_total+1, last_bot_hit_at=? WHERE host=?",
                    (now, host),
                )
                if digest_id and is_search_bot:
                    c.execute("UPDATE digests SET hub_crawled_at=COALESCE(hub_crawled_at, ?) WHERE id=?", (now, digest_id))
                    c.execute(
                        "UPDATE urls SET hub_crawled_at=COALESCE(hub_crawled_at, ?), status='bot_verified', updated_at=? WHERE digest_id=?",
                        (now, now, digest_id),
                    )
                elif not digest_id:
                    ms = SHARD_PATH_RE.match(path)
                    if ms and info["bot_family"] in ("googlebot-2.1", "feedfetcher-google"):
                        shard = int(ms.group(1))
                        c.execute(
                            "UPDATE digests SET hub_crawled_at=COALESCE(hub_crawled_at, ?) WHERE host=? AND shard=?",
                            (now, host, shard),
                        )
                        if is_search_bot:
                            c.execute(
                                """UPDATE urls SET hub_crawled_at=COALESCE(hub_crawled_at, ?), status='bot_verified', updated_at=?
                                   WHERE host=? AND shard=? AND status IN ('published','websub_pinged','feed_crawled')""",
                                (now, now, host, shard),
                            )
                        else:
                            c.execute(
                                """UPDATE urls SET hub_crawled_at=COALESCE(hub_crawled_at, ?), status='feed_crawled', updated_at=?
                                   WHERE host=? AND shard=? AND status IN ('published','websub_pinged')""",
                                (now, now, host, shard),
                            )
    return response


# ------------------------------------------------------------------------------
# Public SSR Discovery Hub (50-URL Topic Digests, Atom+WebSub, Sitemaps, ETag)
# ------------------------------------------------------------------------------
def render_layout(title: str, body: str, base: str, json_ld: dict | None = None) -> str:
    feeds = "\n".join(
        f'<link rel="alternate" type="application/atom+xml" title="{html.escape(SITE_NAME)} Feed {i:02d}" href="{base}/feeds/shard-{i:02d}.atom">'
        for i in range(SHARD_COUNT)
    )
    ld = f'<script type="application/ld+json">{json.dumps(json_ld)}</script>' if json_ld else ""
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} — {html.escape(SITE_NAME)}</title>
<meta name="robots" content="index, follow">
{feeds}
{ld}
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:960px;margin:0 auto;padding:24px;line-height:1.55;color:#111;background:#fafafa}}
header{{border-bottom:1px solid #e5e7eb;padding-bottom:12px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
nav a{{margin-right:14px;color:#2563eb;text-decoration:none;font-weight:500}}
article{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.meta{{font-size:.82rem;color:#6b7280}}
.badge{{display:inline-block;font-size:.72rem;padding:2px 8px;border-radius:999px;background:#eef2ff;color:#3730a3;margin-right:6px}}
ul.items{{padding-left:20px}} ul.items li{{margin-bottom:8px}}
</style>
</head><body>
<header>
  <strong><a href="/" style="color:#111;text-decoration:none">{html.escape(SITE_NAME)}</a></strong>
  <nav><a href="/">Home</a><a href="/latest">Latest Digests</a><a href="/feeds/shard-00.atom">Atom Feed</a><a href="/sitemap.xml">Sitemap</a></nav>
</header>
{body}
<footer class="meta" style="margin-top:32px;border-top:1px solid #e5e7eb;padding-top:12px">{html.escape(SITE_NAME)} • WebSub-enabled Curated Discovery Hub</footer>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    host = effective_host(request)
    base = public_base_url(host)
    with get_conn() as c:
        digests = c.execute("SELECT * FROM digests WHERE host=? ORDER BY id DESC LIMIT 25", (host,)).fetchall()
        if not digests:
            digests = c.execute("SELECT * FROM digests ORDER BY id DESC LIMIT 25").fetchall()
        fresh = c.execute("SELECT * FROM freshness_items ORDER BY id DESC LIMIT 15").fetchall()
    parts = ["<h1>Latest Curated Resource Digests</h1>"]
    for d in digests:
        parts.append(
            f'<article><h2><span class="badge">{html.escape(d["topic"])}</span>'
            f'<a href="/digest/{d["id"]}">Digest #{d["id"]} ({d["url_count"]} resources)</a></h2>'
            f'<div class="meta">Published: {d["created_at"]} • Feed: <a href="/feeds/shard-{d["shard"]:02d}.atom">shard-{d["shard"]:02d}.atom</a></div></article>'
        )
    if fresh:
        parts.append("<h2>Live Public Web &amp; Open-Data Updates</h2>")
        for f in fresh:
            parts.append(
                f'<article><h3><span class="badge">{html.escape(f["source"])}</span>'
                f'<a href="{html.escape(f["link"])}">{html.escape(f["title"])}</a></h3>'
                f'<div class="meta">{f["published_at"]}</div></article>'
            )
    return HTMLResponse(render_layout("Home", "\n".join(parts), base))


@app.get("/latest", response_class=HTMLResponse)
async def latest(request: Request, page: int = 1):
    host = effective_host(request)
    base = public_base_url(host)
    page = max(1, page)
    with get_conn() as c:
        digests = c.execute("SELECT * FROM digests ORDER BY id DESC LIMIT 50 OFFSET ?", ((page - 1) * 50,)).fetchall()
    parts = [f"<h1>Latest Digests — Page {page}</h1>"]
    for d in digests:
        parts.append(
            f'<article><h2><span class="badge">{html.escape(d["topic"])}</span>'
            f'<a href="/digest/{d["id"]}">Digest #{d["id"]} — {d["url_count"]} URLs</a></h2>'
            f'<div class="meta">Host: {html.escape(d["host"])} • {d["created_at"]}</div></article>'
        )
    nav = []
    if page > 1:
        nav.append(f'<a href="/latest?page={page-1}">← Previous</a>')
    if len(digests) == 50:
        nav.append(f'<a href="/latest?page={page+1}">Next →</a>')
    if nav:
        parts.append(f'<p>{" | ".join(nav)}</p>')
    return HTMLResponse(render_layout(f"Latest Digests p.{page}", "\n".join(parts), base))


@app.get("/digest/{digest_id}")
async def digest_page(digest_id: int, request: Request):
    base = public_base_url(effective_host(request))
    with get_conn() as c:
        d = c.execute("SELECT * FROM digests WHERE id=?", (digest_id,)).fetchone()
        if not d:
            raise HTTPException(status_code=404, detail="Digest not found")
        items = c.execute("SELECT * FROM urls WHERE digest_id=? ORDER BY id ASC", (digest_id,)).fetchall()

    etag = '"' + hashlib.sha1(f"{d['id']}:{d['url_count']}:{d['created_at']}".encode()).hexdigest() + '"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})

    lis = []
    ld_items = []
    for idx, it in enumerate(items, 1):
        badge = '<span class="badge">PDF</span>' if it["is_pdf"] else ""
        lis.append(
            f'<li>{badge}<a href="{html.escape(it["url"])}">{html.escape(it["title"] or it["url"])}</a>'
            f'<div class="meta">{html.escape(it["description"] or it["domain"])}</div></li>'
        )
        ld_items.append({"@type": "ListItem", "position": idx, "url": it["url"], "name": it["title"] or it["url"]})
    body = (
        f'<article><h1><span class="badge">{html.escape(d["topic"])}</span>Curated Resource Digest #{d["id"]}</h1>'
        f'<div class="meta">Published {d["created_at"]} • {len(items)} verified resources</div>'
        f'<ul class="items">{"".join(lis)}</ul></article>'
    )
    json_ld = {"@context": "https://schema.org", "@type": "CollectionPage", "name": f"Digest #{d['id']}", "mainEntity": {"@type": "ItemList", "itemListElement": ld_items}}
    return HTMLResponse(render_layout(f"Digest #{d['id']} ({d['topic']})", body, base, json_ld), headers={"ETag": etag})


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots(request: Request):
    base = public_base_url(effective_host(request))
    return f"User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\n\nSitemap: {base}/sitemap.xml\n"


@app.get("/sitemap.xml")
async def sitemap_index(request: Request):
    base = public_base_url(effective_host(request))
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>{xml_escape(base)}/sitemap-digests.xml</loc><lastmod>{utcnow()}</lastmod></sitemap>
</sitemapindex>"""
    return Response(content=xml, media_type="application/xml; charset=utf-8")


@app.get("/sitemap-digests.xml")
async def sitemap_digests(request: Request):
    host = effective_host(request)
    base = public_base_url(host)
    with get_conn() as c:
        rows = c.execute("SELECT id, created_at FROM digests WHERE host=? ORDER BY id DESC LIMIT 5000", (host,)).fetchall()
        if not rows:
            rows = c.execute("SELECT id, created_at FROM digests ORDER BY id DESC LIMIT 5000").fetchall()
    urls = [f"  <url><loc>{xml_escape(base)}/</loc><lastmod>{utcnow()}</lastmod></url>",
            f"  <url><loc>{xml_escape(base)}/latest</loc><lastmod>{utcnow()}</lastmod></url>"]
    for r in rows:
        urls.append(f"  <url><loc>{xml_escape(base)}/digest/{r['id']}</loc><lastmod>{r['created_at']}</lastmod></url>")
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(urls) + "\n</urlset>"
    return Response(content=xml, media_type="application/xml; charset=utf-8")


@app.get("/feeds/shard-{shard:int}.atom")
async def atom_feed(shard: int, request: Request):
    if shard < 0 or shard >= SHARD_COUNT:
        raise HTTPException(status_code=404, detail="Invalid shard")
    host = effective_host(request)
    base = public_base_url(host)
    self_url = f"{base}/feeds/shard-{shard:02d}.atom"
    with get_conn() as c:
        digests = c.execute("SELECT * FROM digests WHERE host=? AND shard=? ORDER BY id DESC LIMIT 25", (host, shard)).fetchall()
        if not digests:
            digests = c.execute("SELECT * FROM digests WHERE shard=? ORDER BY id DESC LIMIT 25", (shard,)).fetchall()
        entries_xml = []
        for d in digests:
            urls = c.execute("SELECT url, title FROM urls WHERE digest_id=? ORDER BY id ASC LIMIT 100", (d["id"],)).fetchall()
            links_html = "".join(f'<li><a href="{html.escape(u["url"])}">{html.escape(u["title"] or u["url"])}</a></li>' for u in urls)
            entries_xml.append(
                f"""  <entry>
    <id>{xml_escape(base)}/digest/{d['id']}</id>
    <title>{xml_escape(f"Digest #{d['id']} ({d['topic']}) — {d['url_count']} resources")}</title>
    <link rel="alternate" href="{xml_escape(base)}/digest/{d['id']}"/>
    <updated>{d['created_at']}</updated>
    <content type="html">{xml_escape(f"<ul>{links_html}</ul>")}</content>
  </entry>"""
            )
    updated = digests[0]["created_at"] if digests else utcnow()
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{xml_escape(self_url)}</id>
  <title>{xml_escape(SITE_NAME)} — Shard {shard:02d}</title>
  <updated>{updated}</updated>
  <link rel="hub" href="{xml_escape(WEBSUB_HUB_URL)}"/>
  <link rel="self" href="{xml_escape(self_url)}"/>
  <link rel="alternate" href="{xml_escape(base)}/latest"/>
{chr(10).join(entries_xml)}
</feed>"""
    return Response(
        content=xml,
        media_type="application/atom+xml; charset=utf-8",
        headers={"Link": f'<{WEBSUB_HUB_URL}>; rel="hub", <{self_url}>; rel="self"', "Cache-Control": "no-store, max-age=0"},
    )


# ------------------------------------------------------------------------------
# Authenticated REST API + Host Failover Controls + Admin Dashboard
# ------------------------------------------------------------------------------
class SubmitPayload(BaseModel):
    urls: list[str]
    skip_preflight: bool = False


class HostStatePayload(BaseModel):
    host: str
    state: str  # warming | active | cooldown


class TargetHitPayload(BaseModel):
    url: str
    ip: str
    ua: str


@app.post("/api/v1/submit", dependencies=[Depends(require_api_key)])
async def submit_urls(payload: SubmitPayload):
    if not payload.urls or len(payload.urls) > 2000:
        raise HTTPException(status_code=400, detail="Provide between 1 and 2,000 URLs per request")
    now = utcnow()
    created = 0
    rejected = 0
    with get_conn() as c:
        for raw in payload.urls:
            u = raw.strip()
            p = urlsplit(u)
            if p.scheme not in ("http", "https") or not p.hostname:
                rejected += 1
                continue
            is_pdf = int(p.path.lower().endswith(".pdf"))
            status = "ready" if payload.skip_preflight else "queued"
            topic = classify_topic(u, "", bool(is_pdf))
            c.execute(
                "INSERT INTO urls (url, domain, is_pdf, topic, title, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (u, p.hostname.lower(), is_pdf, topic, u, status, now, now),
            )
            created += 1
    bus.publish("url_submitted", {"accepted": created, "rejected": rejected, "ts": now})
    return {"ok": True, "accepted": created, "rejected": rejected, "skip_preflight": payload.skip_preflight}


@app.get("/api/v1/stream")
async def sse_stream(key: str):
    if key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    async def gen():
        q = bus.subscribe()
        try:
            yield f"data: {json.dumps({'type': 'connected', 'ts': utcnow()})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class CloudflareProvisionPayload(BaseModel):
    domain: str
    cf_zone_id: str
    cf_api_token: str
    vps_ip: str
    subdomains: list[str] = ["@", "www", "feeds"]
    initial_state: str = "warming"


@app.post("/api/v1/cloudflare/provision", dependencies=[Depends(require_api_key)])
async def provision_cloudflare(payload: CloudflareProvisionPayload):
    domain = payload.domain.strip().lower()
    zone = payload.cf_zone_id.strip()
    token = payload.cf_api_token.strip()
    vps_ip = payload.vps_ip.strip()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    log = []
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=A&per_page=100", headers=headers)
        if r.status_code != 200 or not r.json().get("success"):
            raise HTTPException(status_code=400, detail=f"Cloudflare auth/zone error: {r.text[:300]}")
        by_name = {rec["name"]: rec for rec in r.json().get("result", [])}
        for sub in payload.subdomains:
            fqdn = domain if sub == "@" else f"{sub}.{domain}"
            body = {"type": "A", "name": fqdn, "content": vps_ip, "ttl": 1, "proxied": True}
            if fqdn in by_name:
                ur = await client.put(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{by_name[fqdn]['id']}", headers=headers, json=body)
                log.append(f"DNS PUT {fqdn} -> {vps_ip} ({ur.status_code})")
            else:
                cr = await client.post(f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records", headers=headers, json=body)
                log.append(f"DNS POST {fqdn} -> {vps_ip} ({cr.status_code})")
        sr = await client.patch(f"https://api.cloudflare.com/client/v4/zones/{zone}/settings/ssl", headers=headers, json={"value": "full"})
        log.append(f"SSL mode -> full ({sr.status_code})")

        expr = '(starts_with(http.request.uri.path, "/feeds/") or starts_with(http.request.uri.path, "/sitemap") or starts_with(http.request.uri.path, "/latest") or starts_with(http.request.uri.path, "/digest/"))'
        rule = {"action": "set_cache_settings", "action_parameters": {"cache": False}, "expression": expr, "description": "CrawlHub: bypass cache for live feeds & digests", "enabled": True}
        gr = await client.get(f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/phases/http_request_cache_settings/entrypoint", headers=headers)
        if gr.status_code == 200 and gr.json().get("success"):
            rules = [x for x in gr.json()["result"].get("rules", []) if x.get("description") != rule["description"]] + [rule]
            pr = await client.put(f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets/phases/http_request_cache_settings/entrypoint", headers=headers, json={"rules": rules})
            log.append(f"Cache Bypass Rule updated ({pr.status_code})")
        else:
            pr = await client.post(f"https://api.cloudflare.com/client/v4/zones/{zone}/rulesets", headers=headers, json={"name": "CrawlHub Cache Rules", "kind": "zone", "phase": "http_request_cache_settings", "rules": [rule]})
            log.append(f"Cache Bypass Rule created ({pr.status_code})")

    st = payload.initial_state if payload.initial_state in ("warming", "active", "cooldown") else "warming"
    with get_conn() as c:
        c.execute("INSERT INTO hosts (host, state, created_at) VALUES (?,?,?) ON CONFLICT(host) DO UPDATE SET state=excluded.state", (domain, st, utcnow()))
    return {"ok": True, "domain": domain, "state": st, "steps": log}


class WebSubPingPayload(BaseModel):
    host: str
    shard: int = 0


@app.post("/api/v1/websub/ping", dependencies=[Depends(require_api_key)])
async def manual_websub_ping(payload: WebSubPingPayload):
    base = public_base_url(payload.host)
    feed_url = f"{base}/feeds/shard-{payload.shard:02d}.atom"
    if base.startswith(("http://localhost", "http://127.0.0.1")):
        bus.publish("websub_ping", {"host": payload.host, "shard": payload.shard, "feed_url": feed_url, "status": 204, "ts": utcnow(), "local_only": True})
        return {"ok": True, "feed_url": feed_url, "status": "skipped_localhost", "note": "Localhost URLs cannot be fetched by Google's public WebSub hub; will send real POST on your VPS."}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(WEBSUB_HUB_URL, data={"hub.mode": "publish", "hub.url": feed_url}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    now = utcnow()
    with get_conn() as c:
        c.execute("UPDATE digests SET websub_status=?, websub_pinged_at=? WHERE host=? AND shard=? AND websub_pinged_at IS NULL", (r.status_code, now, payload.host, payload.shard))
        c.execute("UPDATE urls SET status=CASE WHEN status='published' THEN 'websub_pinged' ELSE status END, websub_status=?, websub_pinged_at=?, updated_at=? WHERE host=? AND shard=? AND status='published'", (r.status_code, now, now, payload.host, payload.shard))
    bus.publish("websub_ping", {"host": payload.host, "shard": payload.shard, "feed_url": feed_url, "status": r.status_code, "ts": now})
    return {"ok": True, "feed_url": feed_url, "hub_status": r.status_code}


class RssSourcePayload(BaseModel):
    name: str
    feed_url: str


@app.get("/api/v1/rss-sources", dependencies=[Depends(require_api_key)])
async def list_rss_sources():
    with get_conn() as c:
        sources = [dict(r) for r in c.execute("SELECT * FROM rss_sources ORDER BY id DESC").fetchall()]
        hosts = [r["host"] for r in c.execute("SELECT host FROM hosts ORDER BY host ASC").fetchall()]
    shards = []
    for h in hosts:
        b = public_base_url(h)
        for s in range(SHARD_COUNT):
            shards.append({"host": h, "shard": s, "feed_url": f"{b}/feeds/shard-{s:02d}.atom"})
    return {"ok": True, "external_sources": sources, "outbound_atom_shards": shards}


@app.post("/api/v1/rss-sources", dependencies=[Depends(require_api_key)])
async def add_rss_source(payload: RssSourcePayload):
    with get_conn() as c:
        c.execute("INSERT OR REPLACE INTO rss_sources (name, feed_url, enabled, created_at) VALUES (?,?,1,?)", (payload.name.strip(), payload.feed_url.strip(), utcnow()))
    return {"ok": True}


@app.delete("/api/v1/rss-sources/{source_id}", dependencies=[Depends(require_api_key)])
async def delete_rss_source(source_id: int):
    with get_conn() as c:
        c.execute("DELETE FROM rss_sources WHERE id=?", (source_id,))
    return {"ok": True}


@app.delete("/api/v1/hosts/{host}", dependencies=[Depends(require_api_key)])
async def delete_host(host: str):
    with get_conn() as c:
        c.execute("DELETE FROM hosts WHERE host=?", (host.lower(),))
    return {"ok": True}


@app.post("/api/v1/hosts", dependencies=[Depends(require_api_key)])
async def upsert_host(payload: HostStatePayload):
    if payload.state not in ("warming", "active", "cooldown"):
        raise HTTPException(status_code=400, detail="state must be warming, active, or cooldown")
    h = payload.host.strip().lower()
    with get_conn() as c:
        c.execute(
            "INSERT INTO hosts (host, state, created_at) VALUES (?,?,?) ON CONFLICT(host) DO UPDATE SET state=excluded.state",
            (h, payload.state, utcnow()),
        )
    return {"ok": True, "host": h, "state": payload.state}


@app.get("/api/v1/stats", dependencies=[Depends(require_api_key)])
async def stats(q: Optional[str] = None):
    import datetime as dt
    now = dt.datetime.utcnow()
    t5m = (now - dt.timedelta(minutes=5)).replace(microsecond=0).isoformat() + "Z"
    tday = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat() + "Z"
    with get_conn() as c:
        by_status = dict(c.execute("SELECT status, COUNT(*) FROM urls GROUP BY status").fetchall())
        total_urls = sum(by_status.values())
        hosts_raw = [dict(r) for r in c.execute("SELECT * FROM hosts ORDER BY verified_hits_total DESC, host ASC").fetchall()]
        hosts = []
        for h in hosts_raw:
            hn = h["host"]
            hits_5m = c.execute("SELECT COUNT(*) FROM bot_hits WHERE host=? AND verdict='VERIFIED_BOT' AND ts>=?", (hn, t5m)).fetchone()[0]
            hits_today = c.execute("SELECT COUNT(*) FROM bot_hits WHERE host=? AND verdict='VERIFIED_BOT' AND ts>=?", (hn, tday)).fetchone()[0]
            digests_cnt = c.execute("SELECT COUNT(*) FROM digests WHERE host=?", (hn,)).fetchone()[0]
            last_hit = c.execute("SELECT ts, ip, rdns, bot_family FROM bot_hits WHERE host=? AND verdict='VERIFIED_BOT' ORDER BY id DESC LIMIT 1", (hn,)).fetchone()
            h["hits_5m"] = hits_5m
            h["hits_today"] = hits_today
            h["digests_count"] = digests_cnt
            h["last_ip"] = last_hit["ip"] if last_hit else None
            h["last_rdns"] = last_hit["rdns"] if last_hit else None
            h["last_bot_family"] = last_hit["bot_family"] if last_hit else None
            hosts.append(h)

        digests = [dict(r) for r in c.execute("SELECT * FROM digests ORDER BY id DESC LIMIT 40").fetchall()]
        for d in digests:
            if d["hub_crawled_at"] and d["created_at"]:
                try:
                    t0 = dt.datetime.fromisoformat(d["created_at"].replace("Z", ""))
                    t1 = dt.datetime.fromisoformat(d["hub_crawled_at"].replace("Z", ""))
                    d["latency_sec"] = max(0, int((t1 - t0).total_seconds()))
                except Exception:
                    d["latency_sec"] = None
            else:
                d["latency_sec"] = None

        if q:
            like = f"%{q.strip()}%"
            recent_urls = [dict(r) for r in c.execute("SELECT * FROM urls WHERE url LIKE ? OR domain LIKE ? ORDER BY id DESC LIMIT 100", (like, like)).fetchall()]
        else:
            recent_urls = [dict(r) for r in c.execute("SELECT * FROM urls ORDER BY id DESC LIMIT 50").fetchall()]

        recent_bots = [dict(r) for r in c.execute("SELECT * FROM bot_hits ORDER BY id DESC LIMIT 60").fetchall()]
        bot_counts = dict(c.execute("SELECT bot_family, COUNT(*) FROM bot_hits WHERE verdict='VERIFIED_BOT' GROUP BY bot_family").fetchall())
        spoofed_count = c.execute("SELECT COUNT(*) FROM bot_hits WHERE verdict='SPOOFED_UA'").fetchone()[0]

        latencies = [d["latency_sec"] for d in digests if d["latency_sec"] is not None]
        avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None
        failed = by_status.get("preflight_failed", 0)
        ok_total = total_urls - failed
        success_rate = round((ok_total / total_urls) * 100, 1) if total_urls else 100.0

        # 20-bucket 1-minute live traffic timeline
        timeline = []
        for mins_ago in range(19, -1, -1):
            b0 = (now - dt.timedelta(minutes=mins_ago + 1)).replace(microsecond=0).isoformat() + "Z"
            b1 = (now - dt.timedelta(minutes=mins_ago)).replace(microsecond=0).isoformat() + "Z"
            gb = c.execute("SELECT COUNT(*) FROM bot_hits WHERE verdict='VERIFIED_BOT' AND bot_family='googlebot-2.1' AND ts>=? AND ts<?", (b0, b1)).fetchone()[0]
            ff = c.execute("SELECT COUNT(*) FROM bot_hits WHERE verdict='VERIFIED_BOT' AND bot_family='feedfetcher-google' AND ts>=? AND ts<?", (b0, b1)).fetchone()[0]
            ot = c.execute("SELECT COUNT(*) FROM bot_hits WHERE verdict='VERIFIED_BOT' AND bot_family NOT IN ('googlebot-2.1','feedfetcher-google') AND ts>=? AND ts<?", (b0, b1)).fetchone()[0]
            timeline.append({"label": b1[11:16], "gb": gb, "ff": ff, "ot": ot})

    return {
        "ok": True,
        "server_time_utc": now.replace(microsecond=0).isoformat() + "Z",
        "total_urls": total_urls,
        "urls_by_status": by_status,
        "bot_counts": bot_counts,
        "spoofed_count": spoofed_count,
        "avg_latency_sec": avg_latency,
        "success_rate": success_rate,
        "timeline": timeline,
        "hosts": hosts,
        "recent_digests": digests,
        "recent_urls": recent_urls,
        "recent_bot_hits": recent_bots,
    }


@app.post("/api/v1/urls/retry-failed", dependencies=[Depends(require_api_key)])
async def retry_failed():
    with get_conn() as c:
        cur = c.execute("UPDATE urls SET status='queued', error=NULL, updated_at=? WHERE status='preflight_failed'", (utcnow(),))
    return {"ok": True, "requeued": cur.rowcount}


@app.delete("/api/v1/urls/clear-failed", dependencies=[Depends(require_api_key)])
async def clear_failed():
    with get_conn() as c:
        cur = c.execute("DELETE FROM urls WHERE status='preflight_failed'")
    return {"ok": True, "deleted": cur.rowcount}


@app.post("/api/v1/websub/ping-all", dependencies=[Depends(require_api_key)])
async def ping_all_websub():
    with get_conn() as c:
        hosts = [r["host"] for r in c.execute("SELECT host FROM hosts WHERE state IN ('active','warming')").fetchall()]
    results = []
    async with httpx.AsyncClient(timeout=15) as client:
        for h in hosts:
            base = public_base_url(h)
            for s in range(SHARD_COUNT):
                feed_url = f"{base}/feeds/shard-{s:02d}.atom"
                if base.startswith(("http://localhost", "http://127.0.0.1")):
                    bus.publish("websub_ping", {"host": h, "shard": s, "feed_url": feed_url, "status": 204, "ts": utcnow(), "local_only": True})
                    results.append({"feed_url": feed_url, "status": "local_preview"})
                else:
                    try:
                        r = await client.post(WEBSUB_HUB_URL, data={"hub.mode": "publish", "hub.url": feed_url}, headers={"Content-Type": "application/x-www-form-urlencoded"})
                        bus.publish("websub_ping", {"host": h, "shard": s, "feed_url": feed_url, "status": r.status_code, "ts": utcnow()})
                        results.append({"feed_url": feed_url, "status": r.status_code})
                    except Exception as e:
                        results.append({"feed_url": feed_url, "status": f"err:{type(e).__name__}"})
    return {"ok": True, "pinged": len(results), "results": results}


@app.get("/api/v1/export.csv", dependencies=[Depends(require_api_key)])
async def export_csv():
    import csv, io
    buf = io.StringIO()
    cols = ["id", "status", "topic", "is_pdf", "host", "digest_id", "url", "websub_status", "hub_crawled_at", "target_crawled_at", "created_at"]
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    with get_conn() as c:
        for r in c.execute("SELECT * FROM urls ORDER BY id DESC LIMIT 5000"):
            w.writerow({k: r[k] for k in cols})
    return Response(content=buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=crawlhub-urls.csv"})


@app.post("/api/v1/target-hit", dependencies=[Depends(require_api_key)])
async def ingest_target_hit(payload: TargetHitPayload):
    info = await verifier.verify(payload.ip, payload.ua)
    if not info.get("is_bot") or info.get("verdict") != "VERIFIED_BOT":
        return {"ok": True, "recorded": False}
    now = utcnow()
    with get_conn() as c:
        c.execute("UPDATE urls SET target_crawled_at=COALESCE(target_crawled_at, ?), status='bot_verified', updated_at=? WHERE url=?", (now, now, payload.url))
        c.execute(
            "INSERT INTO bot_hits (ts, ip, host, path, ua, bot_family, verdict, rdns, fcrdns_ok, range_list) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now, payload.ip, "target-worker", payload.url[:300], payload.ua[:300], info["bot_family"], info["verdict"], info["rdns"], int(bool(info["fcrdns_ok"])), info["range_list"]),
        )
    return {"ok": True, "recorded": True, "bot_family": info["bot_family"], "rdns": info["rdns"]}


@app.get("/admin", response_class=HTMLResponse)
async def admin_ui():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "admin.html")
    return FileResponse(p, media_type="text/html; charset=utf-8")
