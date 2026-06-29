"""Public sanitizer for ScamShield VN pipeline.

Transforms processed_private records into public-safe records:
- Strips raw_content, raw_article_text, and private-only fields
- Applies redistribution policy (redact URLs for prohibited/unknown sources)
- Excludes conflict_status=needs_review records
- Re-verifies PII masking
- Computes redistribution_policy_applied flag
"""

import hashlib

from loguru import logger

from src.processors.pii_masker import PIIMasker


class PublicSanitizer:
    """Transforms processed records into public Kaggle-safe output."""

    # Fields to REMOVE from public output
    PRIVATE_FIELDS = [
        "raw_content", "raw_article_text", "source_type_field",
        "source_labels", "source_evidence_levels", "source_types",
        "source_threat_types", "pii_masking_error",
    ]

    # Fields to keep in public output
    PUBLIC_URL_FIELDS = [
        "record_id", "source_ids", "first_seen", "last_seen", "record_type",
        "url", "domain_hash", "url_length", "path_length", "query_length",
        "tld", "has_ip_address", "has_punycode", "has_url_shortener", "domain",
        "label", "scam_types", "evidence_level",
        "redistribution_status", "redistribution_policy_applied", "training_ready",
        "source_type", "credibility_level", "threat_type",
    ]

    PUBLIC_CASE_FIELDS = [
        "record_id", "source_ids", "first_seen", "last_seen", "record_type",
        "summary_vi", "source_url", "scam_types", "label", "evidence_level",
        "summary_method", "human_reviewed", "redistribution_status",
        "redistribution_policy_applied", "training_ready",
        "source_type", "credibility_level",
    ]

    PUBLIC_MESSAGE_FIELDS = [
        "record_id", "source_ids", "first_seen", "last_seen", "record_type",
        "text_sanitized", "benign_message_type", "synthetic",
        "label", "evidence_level", "human_reviewed",
        "redistribution_status", "redistribution_policy_applied", "training_ready",
        "source_type", "credibility_level",
    ]

    def __init__(self):
        self.pii_masker = PIIMasker()

    def sanitize(self, records: list[dict]) -> list[dict]:
        """Transform processed records into public-safe records.
        
        Args:
            records: Processed records from data/processed_private/.
            
        Returns:
            List of public-safe records for data/public_kaggle/.
        """
        public_records = []
        excluded_conflict = 0
        excluded_review = 0

        for record in records:
            # Exclude conflict records
            if record.get("conflict_status") == "needs_review":
                excluded_conflict += 1
                continue

            # Exclude records not public_safe
            if not record.get("public_safe", False):
                excluded_review += 1
                continue

            # Transform to public record
            public_record = self._transform_record(record)
            if public_record:
                public_records.append(public_record)

        logger.info(
            "Public sanitizer: {} records exported, {} excluded (conflict), {} excluded (not public_safe).",
            len(public_records), excluded_conflict, excluded_review
        )
        return public_records

    def _transform_record(self, record: dict) -> dict | None:
        """Transform a single record to public format."""
        public = {}
        record_type = record.get("record_type", "")

        # Strip all private fields
        for field in self.PRIVATE_FIELDS:
            record.pop(field, None)

        # Apply redistribution policy for URL records
        redist_status = record.get("redistribution_status", "unknown")
        
        if record_type == "url":
            if redist_status == "allowed":
                # Keep full URL
                public["redistribution_policy_applied"] = False
                public["url"] = record.get("url")
                public["domain_hash"] = None
            else:
                # Redact URL, keep only derived features
                public["redistribution_policy_applied"] = True
                public["url"] = None
                domain = record.get("domain", "")
                public["domain_hash"] = hashlib.sha256(domain.encode()).hexdigest() if domain else None
        elif record_type == "case":
            public["redistribution_policy_applied"] = redist_status != "allowed"
            # Rename case_summary to summary_vi for public
            public["summary_vi"] = record.get("case_summary")
        elif record_type == "message":
            public["redistribution_policy_applied"] = False
        elif record_type == "domain":
            if redist_status == "allowed":
                public["redistribution_policy_applied"] = False
                public["url"] = None
                public["domain_hash"] = None
            else:
                public["redistribution_policy_applied"] = True
                domain = record.get("domain", "")
                public["domain_hash"] = hashlib.sha256(domain.encode()).hexdigest() if domain else None

        # Copy common fields
        for key in ["record_id", "source_ids", "first_seen", "last_seen", "record_type",
                    "url_length", "path_length", "query_length", "tld", "domain",
                    "has_ip_address", "has_punycode", "has_url_shortener",
                    "label", "scam_types", "evidence_level",
                    "redistribution_status", "training_ready",
                    "source_type", "credibility_level", "threat_type",
                    "text_sanitized", "benign_message_type", "synthetic",
                    "summary_method", "human_reviewed", "source_url",
                    "category", "organization_name", "verification_method"]:
            if key in record and key not in public:
                public[key] = record[key]

        # Ensure redistribution_policy_applied is set
        if "redistribution_policy_applied" not in public:
            public["redistribution_policy_applied"] = False

        return public
