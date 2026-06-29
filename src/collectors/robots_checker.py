"""robots.txt compliance checker for ScamShield VN pipeline.

Fetches and parses robots.txt per domain to verify automated access is permitted.
Results are cached per domain to avoid repeated fetches.
"""

from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx
from loguru import logger


class RobotsChecker:
    """Checks robots.txt compliance before accessing web sources.
    
    Caches parsed robots.txt files per domain. On timeout or fetch failure,
    the domain is treated as disallowed (conservative approach).
    
    Args:
        timeout: Timeout in seconds for fetching robots.txt. Default 10.
        user_agent: User-Agent string used for checking. Default "*".
    """

    def __init__(self, timeout: int = 10, user_agent: str = "*"):
        self.timeout = timeout
        self.user_agent = user_agent
        self._cache: dict[str, RobotFileParser | None] = {}

    def _get_robots_url(self, url: str) -> str:
        """Construct the robots.txt URL for a given page URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    def _get_domain_key(self, url: str) -> str:
        """Extract domain key for caching."""
        parsed = urlparse(url)
        return parsed.netloc

    def _fetch_robots(self, url: str) -> RobotFileParser | None:
        """Fetch and parse robots.txt for a domain. Returns None on failure."""
        robots_url = self._get_robots_url(url)
        domain = self._get_domain_key(url)

        try:
            response = httpx.get(
                robots_url,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                headers={"User-Agent": "ScamShieldVN-RobotsChecker/0.1.0"},
            )

            if response.status_code == 200:
                rp = RobotFileParser()
                rp.parse(response.text.splitlines())
                logger.debug("Parsed robots.txt for domain: {}", domain)
                return rp
            else:
                # Non-200 (404, 403, etc.) - assume everything allowed
                logger.debug(
                    "robots.txt returned {} for domain: {} (assuming allowed)",
                    response.status_code, domain
                )
                rp = RobotFileParser()
                rp.allow_all = True
                return rp

        except (httpx.TimeoutException, httpx.ConnectError, Exception) as e:
            logger.warning(
                "Failed to fetch robots.txt for domain {} ({}): treating as disallowed",
                domain, type(e).__name__
            )
            return None

    def is_allowed(self, url: str) -> bool:
        """Check if the given URL path is allowed by robots.txt.
        
        On timeout or fetch failure, returns False (conservative).
        Results are cached per domain.
        
        Args:
            url: The full URL to check.
            
        Returns:
            True if access is allowed, False if disallowed or on error.
        """
        domain = self._get_domain_key(url)

        # Check cache
        if domain not in self._cache:
            self._cache[domain] = self._fetch_robots(url)

        parser = self._cache[domain]

        if parser is None:
            # Fetch failed - treat as disallowed
            logger.debug("No robots.txt available for {}, treating as disallowed", domain)
            return False

        if hasattr(parser, 'allow_all') and parser.allow_all:
            return True

        allowed = parser.can_fetch(self.user_agent, url)
        if not allowed:
            logger.debug("robots.txt disallows access to: {}", url)
        return allowed

    def clear_cache(self) -> None:
        """Clear the cached robots.txt data."""
        self._cache.clear()
