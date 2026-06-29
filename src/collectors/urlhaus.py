"""URLhaus malware URL collector (abuse.ch)."""

import csv
import io
from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class URLhausCollector(BaseCollector):
    """Collects malware/malicious URLs from URLhaus by abuse.ch.
    
    URLhaus is a project by abuse.ch tracking URLs distributing malware.
    Uses the CSV export (CC0 licensed, freely redistributable).
    Labels records as malware_url, NOT phishing_url.
    """

    CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
    API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    def collect(self) -> list[RawRecord]:
        """Retrieve malware URLs from URLhaus CSV export."""
        records = []
        
        try:
            response = self.http.get(self.CSV_URL)
            
            if response.status_code == 200:
                # URLhaus CSV has comment lines starting with #
                lines = response.text.splitlines()
                data_lines = [l for l in lines if not l.startswith("#") and l.strip()]
                
                if not data_lines:
                    logger.info("URLhaus returned empty dataset.")
                    return []
                
                reader = csv.reader(io.StringIO("\n".join(data_lines)))
                collection_time = datetime.now(timezone.utc)
                
                for row in reader:
                    if len(row) >= 8:
                        # CSV columns: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
                        url = row[2].strip('"')
                        threat_type = row[4].strip('"') if row[4] else "malware"
                        date_added = self._parse_date(row[1].strip('"'))
                        
                        record = RawRecord(
                            source_id=self.source.source_id,
                            collection_timestamp=collection_time,
                            record_type=RecordType.URL,
                            url=url,
                            threat_type=threat_type if threat_type else "malware",
                            date_added=date_added,
                            status=row[3].strip('"') if len(row) > 3 else None,
                        )
                        records.append(record)
                
                logger.info("Parsed {} URLhaus records.", len(records))
            else:
                logger.warning("URLhaus returned status {}", response.status_code)
                
        except Exception as e:
            logger.error("Error collecting from URLhaus: {}", e)
        
        return records

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse URLhaus date format (YYYY-MM-DD HH:MM:SS)."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            return None
