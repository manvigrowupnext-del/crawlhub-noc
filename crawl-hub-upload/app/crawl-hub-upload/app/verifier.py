"""
Real-time crawler verification:
  1. Checks IP against Google's & Bing's official published JSON IP ranges (auto-refreshed hourly).
  2. Performs Forward-Confirmed Reverse DNS (FCrDNS) with a 1-hour in-memory TTL cache.
"""
from __future__ import annotations
import asyncio
import ipaddress
import re
import socket
import time
import httpx

RANGE_URLS = {
    "googlebot": "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "special-crawlers": "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "user-triggered-fetchers-google": "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json",
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
}

BOT_UA_RE = re.compile(
    r"(googlebot|feedfetcher-google|google-inspectiontool|googleother|adsbot-google|bingbot|yandexbot)",
    re.I,
)


class CrawlerVerifier:
    def __init__(self):
        self.networks: dict[str, list[ipaddress._BaseNetwork]] = {}
        self.last_refresh = 0.0
        self.rdns_cache: dict[str, tuple[float, str | None, bool]] = {}

    def classify_ua(self, ua: str) -> str | None:
        u = (ua or "").lower()
        if "googleother" in u:
            return "googleother"
        if "feedfetcher-google" in u:
            return "feedfetcher-google"
        if "google-inspectiontool" in u:
            return "google-inspectiontool"
        if "adsbot-google" in u:
            return "adsbot-google"
        if "googlebot" in u:
            return "googlebot-2.1"
        if "bingbot" in u:
            return "bingbot"
        if "yandexbot" in u:
            return "yandexbot"
        return None

    async def refresh_ranges(self):
        now = time.time()
        if now - self.last_refresh < 3600 and self.networks:
            return
        loaded: dict[str, list[ipaddress._BaseNetwork]] = {}
        async with httpx.AsyncClient(timeout=15) as client:
            for name, url in RANGE_URLS.items():
                try:
                    r = await client.get(url)
                    if r.status_code == 200:
                        data = r.json()
                        nets = []
                        for p in data.get("prefixes", []):
                            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                            if cidr:
                                nets.append(ipaddress.ip_network(cidr))
                        loaded[name] = nets
                except Exception:
                    pass
        if loaded:
            self.networks = loaded
            self.last_refresh = now

    def match_range(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for name, nets in self.networks.items():
            for n in nets:
                if addr in n:
                    return name
        return None

    def _fcrdns_sync(self, ip: str) -> tuple[str | None, bool]:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            return None, False
        ok_suffix = host.endswith(
            (".googlebot.com", ".google.com", ".googleusercontent.com", ".search.msn.com", ".yandex.ru", ".yandex.net")
        )
        if not ok_suffix:
            return host, False
        try:
            fwd = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except Exception:
            fwd = set()
        return host, ip in fwd

    async def verify(self, ip: str, ua: str) -> dict:
        family = self.classify_ua(ua)
        rng = self.match_range(ip)
        if not family and not rng:
            return {"is_bot": False}

        now = time.time()
        cached = self.rdns_cache.get(ip)
        if cached and now - cached[0] < 3600:
            rdns, fcrdns_ok = cached[1], cached[2]
        else:
            rdns, fcrdns_ok = await asyncio.to_thread(self._fcrdns_sync, ip)
            self.rdns_cache[ip] = (now, rdns, fcrdns_ok)

        if rng or fcrdns_ok:
            verdict = "VERIFIED_BOT"
        else:
            verdict = "SPOOFED_UA"

        return {
            "is_bot": True,
            "bot_family": family or (rng or "unknown"),
            "verdict": verdict,
            "rdns": rdns,
            "fcrdns_ok": fcrdns_ok,
            "range_list": rng,
        }


verifier = CrawlerVerifier()
