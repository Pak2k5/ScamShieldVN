"""Redistribution compliance validator."""

from pathlib import Path
import json
from loguru import logger


class RedistributionValidator:
    """Validates redistribution policy compliance in public output."""

    def validate(self, output_dir: str = "./data") -> tuple[bool, list[dict]]:
        """Check that no prohibited/unknown sources have full URLs in public output.
        
        Returns:
            (passed, violations)
        """
        public_dir = Path(output_dir) / "public_kaggle"
        violations = []
        
        jsonl_path = public_dir / "scamshield_vn_public.jsonl"
        if jsonl_path.exists():
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    redist = record.get("redistribution_status", "unknown")
                    url = record.get("url")
                    
                    if redist in ("prohibited", "unknown") and url:
                        violations.append({
                            "record_id": record.get("record_id"),
                            "redistribution_status": redist,
                            "issue": "Full URL present for restricted source",
                        })

        passed = len(violations) == 0
        if passed:
            logger.info("Redistribution validation PASSED.")
        else:
            logger.error("Redistribution validation FAILED: {} violations.", len(violations))
        
        return passed, violations
