"""Conflict detection for ScamShield VN pipeline (Stage 5).

Detects records appearing in both benign and malicious sources.
Uses merged source metadata from deduplication.
"""

from loguru import logger

from src.models.enums import ConflictStatus


class ConflictDetector:
    """Detects label conflicts between benign and malicious sources.
    
    A conflict exists when a record's merged source_types or source_labels
    contain BOTH benign_reference AND threat_feed/official_government malicious indicators.
    
    Conflicting records get conflict_status="needs_review" and are excluded
    from training-ready output until human review.
    """

    BENIGN_TYPES = {"benign_reference"}
    MALICIOUS_TYPES = {"threat_feed", "official_government"}
    BENIGN_LABELS = {"benign_url", "benign_message"}
    MALICIOUS_LABELS = {"phishing_url", "malware_url", "scam_case", "scam_pattern"}

    def detect(self, records: list[dict]) -> list[dict]:
        """Detect benign/malicious conflicts in deduplicated records.
        
        Args:
            records: Deduplicated records with merged source metadata.
            
        Returns:
            Records with conflict_status and conflict_reason set where applicable.
        """
        conflicts_found = 0

        for record in records:
            source_types = record.get("source_types", {})
            source_labels = record.get("source_labels", {})

            # Check type-level conflict
            type_values = set(source_types.values()) if source_types else set()
            has_benign_type = bool(type_values & self.BENIGN_TYPES)
            has_malicious_type = bool(type_values & self.MALICIOUS_TYPES)

            # Check label-level conflict
            label_values = set(source_labels.values()) if source_labels else set()
            has_benign_label = bool(label_values & self.BENIGN_LABELS)
            has_malicious_label = bool(label_values & self.MALICIOUS_LABELS)

            if (has_benign_type and has_malicious_type) or (has_benign_label and has_malicious_label):
                benign_sources = [s for s, t in source_types.items() if t in self.BENIGN_TYPES]
                malicious_sources = [s for s, t in source_types.items() if t in self.MALICIOUS_TYPES]
                
                record["conflict_status"] = ConflictStatus.NEEDS_REVIEW.value
                record["conflict_reason"] = (
                    f"Record has contradicting sources: "
                    f"benign={benign_sources}, malicious={malicious_sources}"
                )
                conflicts_found += 1

        if conflicts_found > 0:
            logger.info("Conflict detection: {} records flagged as needs_review.", conflicts_found)

        return records
