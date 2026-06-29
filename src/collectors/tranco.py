"""Tranco List top domains collector (benign reference)."""

import csv
import io
import zipfile
from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class TrancoCollector(BaseCollector):
    """Collects top 1000 domains from the Tranco ranking list.
    
    Tranco is an aggregated top-domains list combining multiple source rankings.
    Used as international benign domain references.
    """

    LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
    TOP_N = 1000

    def collect(self) -> list[RawRecord]:
        """Download and parse top 1000 domains from Tranco."""
        records = []
        
        try:
            response = self.http.get(self.LIST_URL)
            
            if response.status_code == 200:
                # Tranco provides a ZIP file containing a CSV
                zip_data = io.BytesIO(response.content)
                
                with zipfile.ZipFile(zip_data) as zf:
                    csv_name = zf.namelist()[0]
                    with zf.open(csv_name) as csv_file:
                        reader = csv.reader(io.TextIOWrapper(csv_file, encoding="utf-8"))
                        collection_time = datetime.now(timezone.utc)
                        count = 0
                        
                        for row in reader:
                            if count >= self.TOP_N:
                                break
                            if len(row) >= 2:
                                rank = row[0]
                                domain = row[1].strip()
                                
                                record = RawRecord(
                                    source_id=self.source.source_id,
                                    collection_timestamp=collection_time,
                                    record_type=RecordType.DOMAIN,
                                    domain=domain,
                                    category="international",
                                    verification_method="tranco_ranking",
                                    organization_name=f"Tranco Rank #{rank}",
                                )
                                records.append(record)
                                count += 1
                
                logger.info("Collected top {} domains from Tranco.", len(records))
            else:
                logger.warning("Tranco list returned status {}", response.status_code)
                
        except Exception as e:
            logger.error("Error collecting from Tranco: {}", e)
        
        return records
