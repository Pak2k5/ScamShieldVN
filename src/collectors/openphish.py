"""OpenPhish community phishing feed collector."""

from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class OpenPhishCollector(BaseCollector):
    """Collects phishing URLs from the OpenPhish community feed.
    
    The free community feed provides a plain-text list of phishing URLs.
    Commercial premium feed offers richer data (not used here).
    """

    FEED_URL = "https://openphish.com/feed.txt"

    def collect(self) -> list[RawRecord]:
        """Retrieve current phishing URL feed from OpenPhish."""
        records = []
        
        try:
            response = self.http.get(self.FEED_URL)
            
            if response.status_code == 200:
                lines = response.text.strip().splitlines()
                collection_time = datetime.now(timezone.utc)
                
                for line in lines:
                    url = line.strip()
                    if url and url.startswith(("http://", "https://")):
                        record = RawRecord(
                            source_id=self.source.source_id,
                            collection_timestamp=collection_time,
                            record_type=RecordType.URL,
                            url=url,
                            threat_type="phishing",
                        )
                        records.append(record)
                
                logger.info("Parsed {} OpenPhish URLs.", len(records))
            else:
                logger.warning("OpenPhish returned status {}", response.status_code)
                
        except Exception as e:
            logger.error("Error collecting from OpenPhish: {}", e)
        
        return records
