"""Abstract base collector for ScamShield VN pipeline."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from loguru import logger

from src.config.settings import PipelineConfig
from src.collectors.robots_checker import RobotsChecker
from src.models.record import RawRecord
from src.models.source import SourceEntry
from src.utils.http_client import HttpClient


class BaseCollector(ABC):
    """Abstract base class for all data collectors.
    
    Provides shared infrastructure: HTTP client, robots.txt checking,
    rate limiting, and collection logging.
    """

    def __init__(
        self,
        source: SourceEntry,
        config: PipelineConfig,
        http_client: HttpClient,
        robots_checker: Optional[RobotsChecker] = None,
    ):
        self.source = source
        self.config = config
        self.http = http_client
        self.robots = robots_checker or RobotsChecker()

    def pre_collect_checks(self) -> bool:
        """Run pre-collection compliance checks.
        
        For web sources (public_webpage, public_rss), checks robots.txt.
        Returns False if source should be skipped.
        """
        if self.source.access_method.value in ("public_webpage", "public_rss"):
            if not self.robots.is_allowed(self.source.source_url):
                logger.warning(
                    "Skipping source '{}': robots.txt disallows access to {}",
                    self.source.source_id, self.source.source_url
                )
                return False
        return True

    @abstractmethod
    def collect(self) -> list[RawRecord]:
        """Fetch data from source and return raw records.
        
        Implementations should handle errors gracefully, logging failures
        and returning partial results when possible.
        """
        ...

    def run(self) -> list[RawRecord]:
        """Execute collection with pre-checks and timing."""
        start = datetime.now()
        
        if not self.source.enabled:
            logger.info("Source '{}' is disabled, skipping.", self.source.source_id)
            return []
        
        if not self.pre_collect_checks():
            return []
        
        logger.info("Collecting from source: {} ({})", self.source.source_name, self.source.source_id)
        
        try:
            records = self.collect()
            duration = (datetime.now() - start).total_seconds()
            logger.info(
                "Collected {} records from '{}' in {:.1f}s",
                len(records), self.source.source_id, duration
            )
            return records
        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            logger.error(
                "Collection failed for '{}' after {:.1f}s: {}",
                self.source.source_id, duration, e
            )
            return []
