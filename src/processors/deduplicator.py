"""Hash-based deduplication for ScamShield VN pipeline (Stage 4).

Runs AFTER evidence scoring. Uses evidence_level for tie-breaking.
Preserves source-level metadata for conflict detection.
"""

import hashlib
import uuid
from datetime import datetime

from loguru import logger


class Deduplicator:
    """Deduplicates records based on normalized URL hash.
    
    Keeps record with highest evidence_level (A > B > C > D > E).
    On tie, keeps earliest first_seen. Merges source metadata from duplicates.
    """

    EVIDENCE_ORDER = {"a": 0, "b": 1, "c": 2, "d": 3, "e": 4}

    def compute_url_hash(self, normalized_url: str) -> str:
        """Compute SHA-256 hash of normalized URL for dedup key."""
        return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()

    def deduplicate(self, records: list[dict]) -> list[dict]:
        """Deduplicate records by URL hash, preserving source metadata.
        
        Args:
            records: List of record dicts with at minimum: url_hash, evidence_level,
                     source_id, first_seen, label, source_type, threat_type.
        
        Returns:
            Deduplicated list with merged source metadata and UUID record_ids.
        """
        # Group by url_hash (or by domain for domain records, message_id for messages)
        groups: dict[str, list[dict]] = {}
        non_url_records = []

        for record in records:
            key = record.get("url_hash")
            if not key:
                # Non-URL records (domains, messages) - use domain or message_id as key
                domain_key = record.get("domain")
                msg_key = record.get("message_id")
                key = domain_key or msg_key
            
            if key:
                if key not in groups:
                    groups[key] = []
                groups[key].append(record)
            else:
                non_url_records.append(record)

        # For each group, keep the best record and merge metadata
        deduplicated = []
        duplicates_removed = 0

        for key, group in groups.items():
            if len(group) == 1:
                winner = group[0]
            else:
                # Sort: best evidence first, then earliest first_seen
                group.sort(key=lambda r: (
                    self.EVIDENCE_ORDER.get(r.get("evidence_level", "e"), 4),
                    r.get("first_seen", datetime.max),
                ))
                winner = group[0]
                duplicates_removed += len(group) - 1

                # Merge source metadata from all duplicates
                all_source_ids = []
                source_labels = {}
                source_evidence_levels = {}
                source_types = {}
                source_threat_types = {}
                earliest_seen = winner.get("first_seen")
                latest_seen = winner.get("last_seen", winner.get("first_seen"))

                for rec in group:
                    sid = rec.get("source_id", "")
                    if sid and sid not in all_source_ids:
                        all_source_ids.append(sid)
                    if sid:
                        source_labels[sid] = rec.get("label", "unknown")
                        source_evidence_levels[sid] = rec.get("evidence_level", "e")
                        source_types[sid] = rec.get("source_type", "")
                        if rec.get("threat_type"):
                            source_threat_types[sid] = rec["threat_type"]
                    
                    rec_time = rec.get("first_seen")
                    if rec_time and (not earliest_seen or rec_time < earliest_seen):
                        earliest_seen = rec_time
                    rec_last = rec.get("last_seen", rec.get("first_seen"))
                    if rec_last and (not latest_seen or rec_last > latest_seen):
                        latest_seen = rec_last

                winner["source_ids"] = all_source_ids
                winner["source_labels"] = source_labels
                winner["source_evidence_levels"] = source_evidence_levels
                winner["source_types"] = source_types
                winner["source_threat_types"] = source_threat_types
                winner["first_seen"] = earliest_seen
                winner["last_seen"] = latest_seen

            # Assign UUID record_id
            winner["record_id"] = str(uuid.uuid4())
            
            # Ensure source_ids is a list
            if "source_ids" not in winner:
                sid = winner.get("source_id", "")
                winner["source_ids"] = [sid] if sid else []

            deduplicated.append(winner)

        # Add non-URL records with record_ids
        for rec in non_url_records:
            rec["record_id"] = str(uuid.uuid4())
            if "source_ids" not in rec:
                sid = rec.get("source_id", "")
                rec["source_ids"] = [sid] if sid else []
            deduplicated.append(rec)

        if duplicates_removed > 0:
            logger.info("Deduplication: removed {} duplicates, {} unique records remain.",
                       duplicates_removed, len(deduplicated))
        
        return deduplicated
