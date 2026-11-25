#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Copy .env.example to .env and fill in BASE_DOMAIN, VPS_IP, ADMIN_API_KEY, CF_API_TOKEN, CF_ZONE_ID."
  exit 1
fi

echo "==> 1/3 Bootstrapping Cloudflare DNS + SSL + Cache Rules..."
if command -v python3 >/dev/null 2>&1; then
  python3 -m pip install -q python-dotenv >/dev/null 2>&1 || true
  python3 scripts/cloudflare_bootstrap.py
else
  echo "Skipping Cloudflare bootstrap (python3 not installed locally)."
fi

echo "==> 2/3 Building and starting CrawlHub + Caddy HTTPS proxy..."
docker compose up -d --build

echo "==> 3/3 Done!"
BASE_DOMAIN=$(grep '^BASE_DOMAIN=' .env | cut -d= -f2)
echo "Admin panel : https://${BASE_DOMAIN}/admin"
echo "Atom feed   : https://${BASE_DOMAIN}/feeds/shard-00.atom"
echo "Sitemap     : https://${BASE_DOMAIN}/sitemap.xml"
