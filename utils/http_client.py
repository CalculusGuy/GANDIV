"""
GANDIV HTTP Clients
Sync client (requests) with retry/backoff, async client (aiohttp) with
semaphore-based concurrency limiting, and a simple token-bucket rate limiter.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


def random_ua() -> str:
    return random.choice(USER_AGENTS)


class RateLimiter:
    """Simple blocking token-bucket limiter for synchronous call sites."""

    def __init__(self, rps: float = 3.0):
        self.min_interval = 1.0 / max(rps, 0.01)
        self._last_call = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        remaining = self.min_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_call = time.monotonic()


class AsyncRateLimiter:
    """Async token-bucket limiter for use with aiohttp call sites."""

    def __init__(self, rps: float = 3.0):
        self.min_interval = 1.0 / max(rps, 0.01)
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            elapsed = time.monotonic() - self._last_call
            remaining = self.min_interval - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


class HTTPClient:
    """Synchronous HTTP client with retry/backoff and connection pooling."""

    def __init__(self, timeout: int = 10, max_retries: int = 3, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.session = requests.Session()
        retry = Retry(
            total=max_retries,
            connect=1,  # fail fast on connection-level errors (blocked/unreachable hosts)
            backoff_factor=0.6,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": user_agent or random_ua()})

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", self.timeout)
            return self.session.get(url, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", self.timeout)
            return self.session.post(url, **kwargs)
        except requests.RequestException:
            return None

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", self.timeout)
            return self.session.head(url, **kwargs)
        except requests.RequestException:
            return None

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class AsyncHTTPClient:
    """Asynchronous HTTP client with a concurrency semaphore for fast fan-out
    tasks like checking usernames across hundreds of platforms."""

    def __init__(self, timeout: int = 10, concurrency: int = 30, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.concurrency = concurrency
        self.user_agent = user_agent or random_ua()
        self._session = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def __aenter__(self) -> "AsyncHTTPClient":
        import aiohttp
        self._semaphore = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout, headers={"User-Agent": self.user_agent}
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    async def get(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Returns {'status': int, 'text': str, 'url': str} or None on failure."""
        assert self._session and self._semaphore
        async with self._semaphore:
            try:
                async with self._session.get(url, ssl=False, **kwargs) as resp:
                    text = await resp.text(errors="ignore")
                    return {"status": resp.status, "text": text, "url": str(resp.url)}
            except Exception:
                return None

    async def head(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        assert self._session and self._semaphore
        async with self._semaphore:
            try:
                async with self._session.head(url, ssl=False, allow_redirects=True, **kwargs) as resp:
                    return {"status": resp.status, "url": str(resp.url)}
            except Exception:
                return None
