"""Tín Nhiệm Mạng domain status collector."""

from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class TinNhiemMangCollector(BaseCollector):
    """Collects domain status from Tín Nhiệm Mạng (tinnhiemmang.vn).
    
    Tín Nhiệm Mạng is Vietnam's national cybersecurity trust rating system.
    Respects robots.txt and rate limits. Does not scrape if disallowed.
    """

    BASE_URL = "https://tinnhiemmang.vn"

    def collect(self) -> list[RawRecord]:
        """Collect domain status data from Tín Nhiệm Mạng."""
        # Check robots.txt first
        if not self.robots.is_allowed(f"{self.BASE_URL}/website-lua-dao"):
            logger.warning("Tín Nhiệm Mạng robots.txt disallows access, skipping.")
            return []

        records = []
        collection_time = datetime.now(timezone.utc)

        # Placeholder: In production, would fetch the scam domain list page
        # For now, log that the source is registered but needs manual seed data
        logger.info(
            "Tín Nhiệm Mạng collector registered. "
            "Actual scraping requires robots.txt permission and ToS review."
        )

        return records
