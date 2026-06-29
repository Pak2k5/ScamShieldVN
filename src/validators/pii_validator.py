"""PII validator - re-scans public output for unmasked PII."""

from pathlib import Path
import json
from loguru import logger
from src.processors.pii_masker import PIIMasker


class PIIValidator:
    """Validates that no unmasked PII exists in public_kaggle output."""

    def __init__(self):
        self.masker = PIIMasker()

    def validate(self, output_dir: str = "./data") -> tuple[bool, list[dict]]:
        """Scan all public_kaggle text fields for unmasked PII.
        
        Returns:
            (passed, violations) - True if no PII found, list of violation details.
        """
        public_dir = Path(output_dir) / "public_kaggle"
        violations = []
        
        # Scan JSONL file
        jsonl_path = public_dir / "scamshield_vn_public.jsonl"
        if jsonl_path.exists():
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    for field in ["text_sanitized", "summary_vi", "source_url"]:
                        value = record.get(field)
                        if value and isinstance(value, str):
                            pii_found = self.masker.detect_only(value)
                            if pii_found:
                                violations.append({
                                    "record_id": record.get("record_id", f"line_{line_num}"),
                                    "field": field,
                                    "pii_types": list(pii_found.keys()),
                                    "pii_counts": pii_found,
                                })

        passed = len(violations) == 0
        if passed:
            logger.info("PII validation PASSED: no unmasked PII in public output.")
        else:
            logger.error("PII validation FAILED: {} violations found.", len(violations))
        
        return passed, violations
