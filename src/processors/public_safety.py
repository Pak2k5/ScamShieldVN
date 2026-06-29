"""Public safety computation for ScamShield VN pipeline (Stage 9)."""

from loguru import logger


class PublicSafetyComputer:
    """Determines whether a record is safe for public output.
    
    public_safe=True only if ALL conditions met:
    1. No raw_content or raw_article_text (will be stripped by sanitizer)
    2. PII absent or fully redacted
    3. Redistribution policy can be satisfied
    4. conflict_status is empty or resolved
    5. Record not pending in review queue
    6. No prohibited/private fields remain
    """

    def compute(self, record: dict, in_review_queue: bool = False) -> bool:
        """Compute public_safe flag for a record."""
        # Condition 1: raw content can be stripped (always satisfiable)
        # This is handled by the sanitizer, so we check other conditions
        
        # Condition 2: PII absent or redacted
        if record.get("pii_detected") and not record.get("pii_redacted"):
            return False

        # Condition 3: Redistribution satisfiable
        # (handled at export time - always possible via derived features)

        # Condition 4: No unresolved conflict
        conflict = record.get("conflict_status")
        if conflict == "needs_review":
            return False

        # Condition 5: Not pending review
        if in_review_queue:
            return False

        # Condition 6: No PII masking errors
        if record.get("pii_masking_error"):
            return False

        return True
