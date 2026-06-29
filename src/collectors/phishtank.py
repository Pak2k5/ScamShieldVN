"""PhishTank verified phishing URL collector."""

from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class PhishTankCollector(BaseCollector):
    """Collects verified phishing URLs from the PhishTank API/feed.
    
    PhishTank provides a community-curated list of verified phishing URLs.
    Requires API key for higher rate limits (optional for basic access).
    """

    FEED_URL = "http://data.phishtank.com/data/online-valid.json"

    def collect(self) -> list[RawRecord]:
        """Retrieve verified phishing URLs from PhishTank."""
        records = []
        
        try:
            # Use API key URL if available
            url = self.FEED_URL
            params = {}
            
            response = self.http.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                if not data:
                    logger.info("PhishTank returned empty dataset.")
                    return []
                
                for entry in data:
                    record = RawRecord(
                        source_id=self.source.source_id,
                        collection_timestamp=datetime.now(timezone.utc),
                        record_type=RecordType.URL,
                        url=entry.get("url"),
                        verification_status="verified" if entry.get("verified") == "yes" else "unverified",
                        submission_date=self._parse_date(entry.get("submission_time")),
                        threat_type="phishing",
                    )
                    records.append(record)
                    
                logger.info("Parsed {} PhishTank records.", len(records))
            else:
                logger.warning("PhishTank returned status {}", response.status_code)
                
        except Exception as e:
            logger.error("Error collecting from PhishTank: {}", e)
        
        return records

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse PhishTank date format."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("T", " ").split("+")[0])
        except (ValueError, AttributeError):
            return None
