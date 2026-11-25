---
title: CrawlHub NOC
emoji: 📡
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# CrawlHub — Self-Hosted Batched Discovery Hub (Owned Domains, HF Spaces, or $0 Cloudflare Workers)

Deploy a live, verified-Googlebot discovery hub supporting **50-URL topic digests**, **WebSub (`pubsubhubbub.appspot.com`)**, **ETag/304**, **FCrDNS Googlebot verification**, and **`warming / active / cooldown` multi-host failover**.

## Quick Deploy on Hugging Face Docker Spaces ($0, No Card)
1. Create a Blank **Docker** Space on Hugging Face.
2. In Space **Settings → Variables and secrets**, add:
   - Secret: `ADMIN_API_KEY` (your chosen strong password)
   - Variable: `BASE_DOMAIN` = `<your-user>-<your-space>.hf.space`
3. Upload/push `Dockerfile`, `requirements.txt`, `README.md`, and `app/`.
4. Open `https://<your-user>-<your-space>.hf.space/admin`.

## Option A — VPS + $0 Cloudflare Workers (`*.workers.dev`)
Deploy `cloudflare/hub_proxy_worker.js` pointing `ORIGIN_URL` to your VPS and add the host in `HUB_HOSTS`.

## Option B — VPS + Self-Owned Domains
Fill `.env` (or `cloudflare_zones.json` for up to 10 zones) and run `./deploy.sh`.
