"""Review queue builder for ScamShield VN pipeline (Stage 8)."""

from datetime import datetime, timezone

from loguru import logger

from src.models.enums import RequiresAction


class ReviewQueueBuilder:
    """Aggregates records requiring human review.
    
    Records are flagged for review if any conditions are met:
    - evidence_level C, D, or E
    - redistribution_status = "unknown"
    - conflict_status = "needs_review"
    - PII masking error
    - possible_named_individual = True
    - summary_method = "extractive" AND human_reviewed = False
    - summary_method = "abstractive" AND human_reviewed = False
    """

    def should_review(self, record: dict) -> list[str]:
        """Determine if a record needs human review.
        
        Returns list of review reasons (empty = no review needed).
        """
        reasons = []

        # Evidence level C, D, or E
        evidence = record.get("evidence_level", "e")
        if evidence in ("c", "d", "e"):
            reasons.append(f"evidence_level_{evidence}")

        # Redistribution unknown
        redist = record.get("redistribution_status", "")
        if redist == "unknown":
            reasons.append("redistribution_unknown")

        # Conflict detected
        if record.get("conflict_status") == "needs_review":
            reasons.append("conflict_needs_review")

        # PII masking error
        if record.get("pii_masking_error"):
            reasons.append("pii_masking_error")

        # Named individual detected
        if record.get("possible_named_individual"):
            reasons.append("possible_named_individual")

        # Extractive summary not reviewed
        summary_method = record.get("summary_method", "")
        human_reviewed = record.get("human_reviewed", False)
        if summary_method == "extractive" and not human_reviewed:
            reasons.append("extractive_summary_not_reviewed")
        if summary_method == "abstractive" and not human_reviewed:
            reasons.append("abstractive_summary_not_reviewed")

        return reasons

    def build_queue(self, records: list[dict]) -> list[dict]:
        """Build the review queue from all records.
        
        Returns list of review queue entries.
        """
        queue = []

        for record in records:
            reasons = self.should_review(record)
            if reasons:
                entry = {
                    "record_id": record.get("record_id", ""),
                    "review_reason": reasons,
                    "source_ids": record.get("source_ids", []),
                    "label": record.get("label", "unknown"),
                    "evidence_level": record.get("evidence_level", "e"),
                    "conflict_status": record.get("conflict_status"),
                    "pii_detected": record.get("pii_detected", False),
                    "requires_action": RequiresAction.APPROVE.value,
                    "reviewer_assigned": None,
                    "reviewed_by": None,
                    "reviewed_at": None,
                    "review_notes": None,
                }
                queue.append(entry)

        logger.info("Review queue: {} records require human review.", len(queue))
        return queue
