#!/usr/bin/env python3
"""
cloudflare_bootstrap.py - Automatically configures 1 or up to 10 Cloudflare zones using scoped API tokens.

Modes:
  1. Multi-zone mode (recommended when managing multiple zones/accounts):
     Copy cloudflare_zones.example.json -> cloudflare_zones.json (up to 10 entries) and run:
       python3 scripts/cloudflare_bootstrap.py
  2. Single-zone mode (fallback when cloudflare_zones.json does not exist):
     Reads CF_API_TOKEN, CF_ZONE_ID, BASE_DOMAIN, VPS_IP from .env.

For each zone, idempotently configures:
  - Proxied (orange-cloud) DNS A records pointing to vps_ip
  - SSL/TLS encryption mode -> full
  - Cloudflare Cache Bypass Rule for /feeds/*, /sitemap*, /latest*, /digest/*
"""
from __future__ import annotations
import json
import os
import sys
import urllib.error
import urllib.request
from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

MAX_ZONES = 10
DEFAULT_SUBS = ["@", "www", "hub1", "feeds", "digest"]


def cf(token: str, method: str, path: str, body: dict | None = None) -> dict:
    url = f"https://api.cloudflare.com/client/v4{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        raise RuntimeError(f"Cloudflare API {e.code} on {method} {path}: {err}")


def configure_zone(z: dict):
    label = z.get("label") or z["domain"]
    token = z["cf_api_token"].strip()
    zone = z["cf_zone_id"].strip()
    domain = z["domain"].strip().lower()
    vps_ip = z["vps_ip"].strip()
    subs = z.get("subdomains") or DEFAULT_SUBS

    print(f"\n=== Configuring {label} ({domain}) ===")
    existing = cf(token, "GET", f"/zones/{zone}/dns_records?type=A&per_page=100")["result"]
    by_name = {r["name"]: r for r in existing}
    for sub in subs:
        fqdn = domain if sub == "@" else f"{sub}.{domain}"
        payload = {"type": "A", "name": fqdn, "content": vps_ip, "ttl": 1, "proxied": True}
        if fqdn in by_name:
            cf(token, "PUT", f"/zones/{zone}/dns_records/{by_name[fqdn]['id']}", payload)
            print(f"  [DNS] Updated A {fqdn} -> {vps_ip} (proxied)")
        else:
            cf(token, "POST", f"/zones/{zone}/dns_records", payload)
            print(f"  [DNS] Created A {fqdn} -> {vps_ip} (proxied)")

    cf(token, "PATCH", f"/zones/{zone}/settings/ssl", {"value": "full"})
    print("  [SSL] Set SSL/TLS mode -> full")

    expr = (
        '(starts_with(http.request.uri.path, "/feeds/") or '
        'starts_with(http.request.uri.path, "/sitemap") or '
        'starts_with(http.request.uri.path, "/latest") or '
        'starts_with(http.request.uri.path, "/digest/"))'
    )
    rule = {
        "action": "set_cache_settings",
        "action_parameters": {"cache": False},
        "expression": expr,
        "description": "CrawlHub: bypass cache for live Atom feeds, sitemaps, and digests",
        "enabled": True,
    }
    try:
        rs = cf(token, "GET", f"/zones/{zone}/rulesets/phases/http_request_cache_settings/entrypoint")["result"]
        rules = [r for r in rs.get("rules", []) if r.get("description") != rule["description"]]
        rules.append(rule)
        cf(token, "PUT", f"/zones/{zone}/rulesets/phases/http_request_cache_settings/entrypoint", {"rules": rules})
    except RuntimeError:
        cf(
            token,
            "POST",
            f"/zones/{zone}/rulesets",
            {"name": "CrawlHub Cache Rules", "kind": "zone", "phase": "http_request_cache_settings", "rules": [rule]},
        )
    print("  [CACHE] Bypass rule active for /feeds/*, /sitemap*, /latest*, /digest/*")


def load_zones() -> list[dict]:
    zpath = os.path.join(ROOT, "cloudflare_zones.json")
    if os.path.exists(zpath):
        zones = json.load(open(zpath))
        if not isinstance(zones, list) or not zones:
            sys.exit("cloudflare_zones.json must be a non-empty JSON list")
        if len(zones) > MAX_ZONES:
            sys.exit(f"Refusing {len(zones)} zones: hard limit is {MAX_ZONES} zones.")
        return zones

    token = os.getenv("CF_API_TOKEN", "").strip()
    zone = os.getenv("CF_ZONE_ID", "").strip()
    domain = os.getenv("BASE_DOMAIN", "").strip()
    vps_ip = os.getenv("VPS_IP", "").strip()
    missing = [k for k, v in [("CF_API_TOKEN", token), ("CF_ZONE_ID", zone), ("BASE_DOMAIN", domain), ("VPS_IP", vps_ip)] if not v]
    if missing:
        sys.exit(f"Missing .env variables ({', '.join(missing)}) and cloudflare_zones.json not found.")
    return [{"label": "default", "domain": domain, "cf_zone_id": zone, "cf_api_token": token, "vps_ip": vps_ip}]


def main():
    zones = load_zones()
    configured_hosts = []
    for z in zones:
        configure_zone(z)
        configured_hosts.append(z["domain"].strip().lower())
    print("\nAll zones configured!")
    print("Suggested HUB_HOSTS for .env:")
    print("  HUB_HOSTS=" + ",".join(configured_hosts))


if __name__ == "__main__":
    main()
