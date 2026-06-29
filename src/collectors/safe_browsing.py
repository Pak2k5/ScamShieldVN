"""Google Safe Browsing API enrichment collector."""

from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.record import RawRecord


class SafeBrowsingEnricher(BaseCollector):
    """Enriches collected URLs by checking against Google Safe Browsing API.
    
    Requires SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY. Skips if not configured.
    Batch-checks up to 500 URLs per request per API limits.
    Does NOT collect new URLs, only enriches existing records.
    """

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    BATCH_SIZE = 500

    def __init__(self, *args, api_key: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = api_key

    def collect(self) -> list[RawRecord]:
        """Not used directly. Use enrich() instead."""
        logger.info("SafeBrowsingEnricher.collect() is a no-op. Use enrich() for URL enrichment.")
        return []

    def enrich(self, records: list[RawRecord]) -> list[RawRecord]:
        """Check URLs against Safe Browsing and add threat_match field."""
        if not self.api_key:
            logger.info("Google Safe Browsing API key not configured, skipping enrichment.")
            return records

        urls = [r.url for r in records if r.url]
        
        # Process in batches of 500
        threat_matches: dict[str, bool] = {}
        for i in range(0, len(urls), self.BATCH_SIZE):
            batch = urls[i:i + self.BATCH_SIZE]
            matches = self._check_batch(batch)
            threat_matches.update(matches)

        # Apply enrichment
        for record in records:
            if record.url and record.url in threat_matches:
                record.threat_match = threat_matches[record.url]

        matched = sum(1 for v in threat_matches.values() if v)
        logger.info("Safe Browsing enrichment: {}/{} URLs flagged as threats.", matched, len(urls))
        return records

    def _check_batch(self, urls: list[str]) -> dict[str, bool]:
        """Check a batch of URLs against the Safe Browsing API."""
        results = {}
        try:
            payload = {
                "client": {"clientId": "scamshield-vn", "clientVersion": "0.1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in urls],
                },
            }
            response = self.http._client.post(
                f"{self.API_URL}?key={self.api_key}",
                json=payload,
            )
            if response.status_code == 200:
                data = response.json()
                matched_urls = set()
                for match in data.get("matches", []):
                    matched_urls.add(match.get("threat", {}).get("url", ""))
                for url in urls:
                    results[url] = url in matched_urls
            else:
                logger.warning("Safe Browsing API returned {}", response.status_code)
                for url in urls:
                    results[url] = False
        except Exception as e:
            logger.error("Safe Browsing batch check error: {}", e)
            for url in urls:
                results[url] = False
        return results
