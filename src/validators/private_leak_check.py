"""Private data leakage detector."""

from pathlib import Path
import json
from loguru import logger


class PrivateLeakChecker:
    """Checks that no private data leaked into public output."""

    FORBIDDEN_FIELDS = ["raw_content", "raw_article_text", "source_labels", 
                        "source_evidence_levels", "source_types", "source_threat_types"]

    def validate(self, output_dir: str = "./data") -> tuple[bool, list[str]]:
        """Check for private data leakage.
        
        Checks:
        1. No forbidden fields in public JSONL
        2. No private_raw files referenced in public_kaggle
        
        Returns:
            (passed, issues)
        """
        public_dir = Path(output_dir) / "public_kaggle"
        issues = []

        # Check JSONL for forbidden fields
        jsonl_path = public_dir / "scamshield_vn_public.jsonl"
        if jsonl_path.exists():
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    for field in self.FORBIDDEN_FIELDS:
                        if field in record and record[field]:
                            issues.append(f"Line {line_num}: forbidden field '{field}' present")

        # Check no private_raw reference
        private_raw = Path(output_dir) / "private_raw"
        if private_raw.exists():
            for public_file in public_dir.iterdir():
                if public_file.is_file() and public_file.suffix in (".jsonl", ".csv"):
                    content = public_file.read_text(encoding="utf-8", errors="ignore")
                    if "private_raw" in content:
                        issues.append(f"{public_file.name}: references 'private_raw'")

        passed = len(issues) == 0
        if passed:
            logger.info("Private leak check PASSED.")
        else:
            logger.error("Private leak check FAILED: {} issues.", len(issues))
        
        return passed, issues
