from __future__ import annotations
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DOMAIN = os.getenv("BASE_DOMAIN", "localhost").strip().rstrip("/")
_raw_hosts = os.getenv("HUB_HOSTS", "").strip()
HUB_HOSTS = [h.strip().lower() for h in _raw_hosts.split(",") if h.strip()] or [BASE_DOMAIN.lower()]

SITE_NAME = os.getenv("SITE_NAME", "Open Web Index & Feed Hub").strip()
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "dev-secret-change-me").strip()
DB_PATH = os.getenv("DB_PATH", os.path.join(os.getcwd(), "data", "crawlhub.db"))
SHARD_COUNT = max(1, min(32, int(os.getenv("SHARD_COUNT", "4"))))
DIGEST_BATCH_SIZE = max(5, min(200, int(os.getenv("DIGEST_BATCH_SIZE", "50"))))
DIGEST_FLUSH_SECONDS = max(15, int(os.getenv("DIGEST_FLUSH_SECONDS", "120")))
PREFLIGHT_CONCURRENCY = max(1, min(100, int(os.getenv("PREFLIGHT_CONCURRENCY", "25"))))
PREFLIGHT_PROXY_URL = os.getenv("PREFLIGHT_PROXY_URL", "").strip() or None
WEBSUB_HUB_URL = os.getenv("WEBSUB_HUB_URL", "https://pubsubhubbub.appspot.com/").strip()
WEBSUB_BATCH_SECONDS = max(5, int(os.getenv("WEBSUB_BATCH_SECONDS", "20")))
PREFLIGHT_TIMEOUT = max(3, int(os.getenv("PREFLIGHT_TIMEOUT_SECONDS", "12")))
TRUST_CF_IP = os.getenv("TRUST_CF_CONNECTING_IP", "true").lower() == "true"
TELEGRAPH_DIGEST_EVERY = int(os.getenv("TELEGRAPH_DIGEST_EVERY", "0"))
ENABLE_FRESHNESS = os.getenv("ENABLE_FRESHNESS_WARMUP", "true").lower() == "true"
FRESHNESS_INTERVAL_MIN = max(10, int(os.getenv("FRESHNESS_INTERVAL_MINUTES", "30")))


def public_base_url(host: str | None = None) -> str:
    h = (host or BASE_DOMAIN).split(":")[0]
    if h in ("localhost", "127.0.0.1"):
        return f"http://{host or 'localhost:8000'}"
    return f"https://{h}"
