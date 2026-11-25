/**
 * Optional Cloudflare Worker for Target Domains You Own
 *
 * Attach this Worker as a route on any target domain you control (e.g. targetdomain.com/*)
 * to report real, target-side Googlebot/Bingbot/YandexBot hits directly to your CrawlHub dashboard.
 *
 * Environment variables to set on the Worker:
 *   CRAWLHUB_INGEST_URL = "https://yourcrawlhub.com/api/v1/target-hit"
 *   CRAWLHUB_API_KEY    = "<your ADMIN_API_KEY>"
 */
const BOT_RE = /googlebot|feedfetcher-google|google-inspectiontool|bingbot|yandexbot/i;

export default {
  async fetch(request, env, ctx) {
    const response = await fetch(request);
    const ua = request.headers.get("user-agent") || "";
    if (BOT_RE.test(ua)) {
      const ip = request.headers.get("cf-connecting-ip") || "";
      ctx.waitUntil(
        fetch(env.CRAWLHUB_INGEST_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": env.CRAWLHUB_API_KEY,
          },
          body: JSON.stringify({ url: request.url, ip, ua }),
        }).catch(() => {})
      );
    }
    return response;
  },
};
