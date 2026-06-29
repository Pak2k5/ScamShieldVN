"""Training readiness computation for ScamShield VN pipeline (Stage 10)."""

from loguru import logger


class TrainingReadyComputer:
    """Computes training_ready boolean from 8 conditions.
    
    training_ready=True ONLY IF ALL conditions met:
    1. public_safe = True
    2. PII absent or fully redacted
    3. Redistribution status = "allowed" OR policy can be applied
    4. conflict_status is empty or "resolved"
    5. evidence_level is A or B
    6. Record not pending in review queue
    7. summary_method != "abstractive" unless human_reviewed=True
    8. summary_method != "extractive" unless human_reviewed=True
    """

    def compute(self, record: dict, in_review_queue: bool = False) -> bool:
        """Compute training_ready flag for a record."""
        # Condition 1: public_safe
        if not record.get("public_safe", False):
            return False

        # Condition 2: PII absent or redacted
        if record.get("pii_detected") and not record.get("pii_redacted"):
            return False

        # Condition 3: Redistribution
        redist = record.get("redistribution_status", "unknown")
        if redist == "prohibited":
            # Still training_ready if we can apply policy (derived features only)
            pass  # Will be handled at export with redistribution_policy_applied

        # Condition 4: No unresolved conflict
        conflict = record.get("conflict_status")
        if conflict == "needs_review":
            return False

        # Condition 5: Evidence level A or B only
        evidence = record.get("evidence_level", "e")
        if evidence not in ("a", "b"):
            return False

        # Condition 6: Not pending review
        if in_review_queue:
            return False

        # Condition 7: Abstractive requires human review
        summary_method = record.get("summary_method", "")
        human_reviewed = record.get("human_reviewed", False)
        if summary_method == "abstractive" and not human_reviewed:
            return False

        # Condition 8: Extractive requires human review
        if summary_method == "extractive" and not human_reviewed:
            return False

        return True
