"""Vietnamese official source collector (seed-based, no broad crawling)."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class VietnameseOfficialCollector(BaseCollector):
    """Collects case metadata from curated Vietnamese official seed URLs.
    
    Operates ONLY from seed URLs defined in config/vietnamese_sources.yaml.
    Does NOT perform broad crawling. Respects robots.txt and rate limits.
    Stores only metadata and paraphrased summaries (max 120 words), never full articles.
    """

    def collect(self) -> list[RawRecord]:
        """Collect case metadata from Vietnamese official seed URLs."""
        seeds = self._load_seeds()
        if not seeds:
            logger.warning("No Vietnamese source seeds found.")
            return []

        records = []
        collection_time = datetime.now(timezone.utc)

        for seed in seeds:
            url = seed.get("url", "")
            if not url:
                continue

            # Check robots.txt for each seed URL
            if not self.robots.is_allowed(url):
                logger.warning("robots.txt disallows: {} - skipping", url)
                continue

            # Placeholder: In production, this would fetch and parse the page
            # For now, create a metadata record from the seed definition
            record = RawRecord(
                source_id=self.source.source_id,
                collection_timestamp=collection_time,
                record_type=RecordType.CASE,
                source_url=url,
                case_summary=f"[Seed URL registered] {seed.get('source_name', '')}",
                scam_type=None,
                date_reported=collection_time,
                summary_method="rule_based",
                human_reviewed=False,
            )
            records.append(record)

        logger.info("Registered {} Vietnamese official seed URLs.", len(records))
        return records

    def _load_seeds(self) -> list[dict]:
        """Load seed URLs from config/vietnamese_sources.yaml."""
        seed_path = Path("config/vietnamese_sources.yaml")
        if not seed_path.exists():
            logger.warning("Vietnamese sources config not found: {}", seed_path)
            return []

        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data.get("vietnamese_sources", [])
        except Exception as e:
            logger.error("Error loading Vietnamese sources config: {}", e)
            return []
