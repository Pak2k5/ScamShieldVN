"""Shared HTTP client with rate limiting and retry for ScamShield VN pipeline."""

import asyncio
import time
from typing import Optional

import httpx
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)


class RateLimiter:
    """Simple per-domain rate limiter using token bucket approach."""

    def __init__(self, requests_per_second: float = 1.0):
        self.min_interval = 1.0 / requests_per_second
        self._last_request_time: dict[str, float] = {}

    def wait_if_needed(self, domain: str) -> None:
        """Block until rate limit allows a request to this domain."""
        now = time.monotonic()
        last = self._last_request_time.get(domain, 0.0)
        elapsed = now - last
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.debug("Rate limiting: sleeping {:.2f}s for domain {}", sleep_time, domain)
            time.sleep(sleep_time)
        self._last_request_time[domain] = time.monotonic()


class HttpClient:
    """HTTP client with retry, rate limiting, and timeout configuration.
    
    Wraps httpx for synchronous requests with:
    - Configurable timeout (default 30s)
    - Per-domain rate limiting
    - Automatic retry on 5xx/connection errors (3 attempts, exponential backoff)
    - No retry on 4xx client errors
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_base: int = 2,
        backoff_max: int = 30,
        rate_limit_rps: float = 1.0,
        user_agent: str = "ScamShieldVN-DataPipeline/0.1.0 (research)",
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.rate_limiter = RateLimiter(rate_limit_rps)
        self.user_agent = user_agent
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": user_agent},
            follow_redirects=True,
        )

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for rate limiting."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.hostname or "unknown"

    def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request with rate limiting and retry logic.
        
        Retries on HTTP 5xx, ConnectionError, TimeoutError (up to max_retries).
        Does NOT retry on HTTP 4xx (logs warning and raises).
        
        Args:
            url: Target URL.
            **kwargs: Additional httpx request kwargs.
            
        Returns:
            httpx.Response on success.
            
        Raises:
            httpx.HTTPStatusError: On 4xx errors (no retry).
            Exception: After max retries exhausted on 5xx/network errors.
        """
        domain = self._extract_domain(url)
        self.rate_limiter.wait_if_needed(domain)
        return self._get_with_retry(url, **kwargs)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, ConnectionError, TimeoutError)),
        reraise=True,
    )
    def _get_with_retry(self, url: str, **kwargs) -> httpx.Response:
        """Internal GET with tenacity retry on transient errors."""
        try:
            response = self._client.get(url, **kwargs)
            
            # Don't retry 4xx
            if 400 <= response.status_code < 500:
                logger.warning(
                    "HTTP {} client error for URL: {} (no retry)",
                    response.status_code, url
                )
                response.raise_for_status()
            
            # Retry 5xx
            if response.status_code >= 500:
                logger.warning(
                    "HTTP {} server error for URL: {} (will retry)",
                    response.status_code, url
                )
                raise httpx.HTTPStatusError(
                    f"Server error {response.status_code}",
                    request=response.request,
                    response=response,
                )
            
            return response
            
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            logger.warning("Network error for URL {}: {} (will retry)", url, type(e).__name__)
            raise

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
