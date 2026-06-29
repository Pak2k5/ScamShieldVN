"""VirusTotal API enrichment collector."""

from typing import Optional

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.record import RawRecord


class VirusTotalEnricher(BaseCollector):
    """Enriches collected URLs with VirusTotal detection statistics.
    
    Requires SCAMSHIELD_VIRUSTOTAL_KEY. Skips if not configured.
    Queries 1 URL at a time due to strict rate limits (4 req/min free tier).
    """

    API_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, *args, api_key: Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = api_key

    def collect(self) -> list[RawRecord]:
        """Not used directly. Use enrich() instead."""
        logger.info("VirusTotalEnricher.collect() is a no-op. Use enrich() for URL enrichment.")
        return []

    def enrich(self, records: list[RawRecord], max_urls: int = 50) -> list[RawRecord]:
        """Query VirusTotal for URL detection stats. Limited to max_urls to respect rate limits."""
        if not self.api_key:
            logger.info("VirusTotal API key not configured, skipping enrichment.")
            return records

        url_records = [r for r in records if r.url][:max_urls]
        
        for record in url_records:
            stats = self._check_url(record.url)
            if stats:
                record.positives_count = stats.get("malicious", 0)
                record.total_engines = stats.get("total", 0)

        logger.info("VirusTotal enrichment: checked {} URLs.", len(url_records))
        return records

    def _check_url(self, url: str) -> Optional[dict]:
        """Query a single URL against VirusTotal."""
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            response = self.http._client.get(
                f"{self.API_URL}/{url_id}",
                headers={"x-apikey": self.api_key},
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "total": sum(stats.values()) if stats else 0,
                }
            elif response.status_code == 404:
                return None
            else:
                logger.debug("VT returned {} for URL: {}", response.status_code, url[:50])
                return None
        except Exception as e:
            logger.debug("VT check error for {}: {}", url[:50], e)
            return None
