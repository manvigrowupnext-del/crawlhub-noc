/**
 * Zero-Domain Free Option: Cloudflare Worker Reverse Proxy (*.workers.dev)
 *
 * Deploy this 20-line Worker on your FREE Cloudflare account at e.g.:
 *   https://hub1.<your-subdomain>.workers.dev
 *
 * Set ONE Worker environment variable:
 *   ORIGIN_URL = "http://<YOUR_VPS_IP>:8000"   (or "https://your-origin-host")
 *
 * Then add `hub1.<your-subdomain>.workers.dev` to HUB_HOSTS in your VPS .env!
 * Benefits:
 *   - $0 domain cost, instant HTTPS, 100,000 free requests/day per account
 *   - Forwards real CF-Connecting-IP so your VPS still runs live FCrDNS Googlebot verification
 *   - Bypassed cache on /feeds/*, /sitemap*, /digest/* so Googlebot always sees fresh digests
 */
export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    const origin = new URL(env.ORIGIN_URL);
    origin.pathname = incoming.pathname;
    origin.search = incoming.search;

    const headers = new Headers(request.headers);
    headers.set("X-Forwarded-Host", incoming.host);
    const cfIp = request.headers.get("cf-connecting-ip");
    if (cfIp) headers.set("CF-Connecting-IP", cfIp);

    const bypass =
      incoming.pathname.startsWith("/feeds/") ||
      incoming.pathname.startsWith("/sitemap") ||
      incoming.pathname.startsWith("/digest/") ||
      incoming.pathname.startsWith("/latest");

    return fetch(origin.toString(), {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      cf: bypass ? { cacheTtl: 0, cacheEverything: false } : undefined,
    });
  },
};
