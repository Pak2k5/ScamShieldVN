"""Kaggle publication gate - 11-point checklist."""

from pathlib import Path
import json
from loguru import logger

from src.validators.pii_validator import PIIValidator
from src.validators.redistribution_validator import RedistributionValidator
from src.validators.private_leak_check import PrivateLeakChecker


class KaggleGate:
    """Runs 11-point Kaggle publication gate. ALL must pass."""

    def __init__(self, output_dir: str = "./data"):
        self.output_dir = output_dir
        self.public_dir = Path(output_dir) / "public_kaggle"

    def run_checks(self) -> dict:
        """Run all 11 checks. Returns dict with results."""
        results = {}

        # 1. PII absence
        pii_val = PIIValidator()
        pii_passed, pii_violations = pii_val.validate(self.output_dir)
        results["pii_absence"] = {"passed": pii_passed, "details": f"{len(pii_violations)} violations"}

        # 2. License compliance
        license_passed = (self.public_dir / "LICENSE_NOTES.md").exists()
        results["license_compliance"] = {"passed": license_passed, "details": "LICENSE_NOTES.md present" if license_passed else "MISSING"}

        # 3. Redistribution compliance
        redist_val = RedistributionValidator()
        redist_passed, redist_violations = redist_val.validate(self.output_dir)
        results["redistribution_compliance"] = {"passed": redist_passed, "details": f"{len(redist_violations)} violations"}

        # 4. Conflict records excluded
        conflict_passed = self._check_no_conflicts()
        results["conflict_excluded"] = {"passed": conflict_passed, "details": "No conflict records in public" if conflict_passed else "CONFLICT RECORDS FOUND"}

        # 5. Private data excluded
        leak_check = PrivateLeakChecker()
        leak_passed, leak_issues = leak_check.validate(self.output_dir)
        results["private_data_excluded"] = {"passed": leak_passed, "details": f"{len(leak_issues)} issues"}

        # 6. Copyright excluded (no raw_article_text)
        copyright_passed = self._check_no_copyright()
        results["copyright_excluded"] = {"passed": copyright_passed, "details": "No copyrighted content"}

        # 7. Extractive summaries reviewed
        extractive_passed = self._check_extractive_reviewed()
        results["extractive_reviewed"] = {"passed": extractive_passed, "details": "OK"}

        # 8. Dataset card present
        card_passed = (self.public_dir / "dataset_card.md").exists()
        results["dataset_card_present"] = {"passed": card_passed, "details": "dataset_card.md present" if card_passed else "MISSING"}

        # 9. README present
        readme_passed = (self.public_dir / "README.md").exists()
        results["readme_present"] = {"passed": readme_passed, "details": "README.md present" if readme_passed else "MISSING"}

        # 10. Manifest present
        manifest_passed = (self.public_dir / "data_manifest.json").exists()
        results["manifest_present"] = {"passed": manifest_passed, "details": "data_manifest.json present" if manifest_passed else "MISSING"}

        # 11. Minimum records (100 training-ready)
        min_passed, count = self._check_minimum_records()
        results["minimum_records"] = {"passed": min_passed, "details": f"{count} training-ready records"}

        return results

    def _check_no_conflicts(self) -> bool:
        jsonl_path = self.public_dir / "scamshield_vn_public.jsonl"
        if not jsonl_path.exists():
            return True
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("conflict_status") == "needs_review":
                    return False
        return True

    def _check_no_copyright(self) -> bool:
        jsonl_path = self.public_dir / "scamshield_vn_public.jsonl"
        if not jsonl_path.exists():
            return True
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                if "raw_article_text" in record and record["raw_article_text"]:
                    return False
        return True

    def _check_extractive_reviewed(self) -> bool:
        jsonl_path = self.public_dir / "scamshield_vn_public.jsonl"
        if not jsonl_path.exists():
            return True
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("summary_method") == "extractive" and not record.get("human_reviewed"):
                    return False
        return True

    def _check_minimum_records(self) -> tuple[bool, int]:
        jsonl_path = self.public_dir / "scamshield_vn_public.jsonl"
        if not jsonl_path.exists():
            return False, 0
        count = 0
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("training_ready"):
                    count += 1
        return count >= 100, count

    def generate_report(self, results: dict) -> str:
        """Generate Markdown checklist report."""
        lines = ["# Kaggle Publication Gate\n"]
        lines.append("| # | Check | Status | Details |")
        lines.append("|---|-------|--------|---------|")
        
        checks = [
            (1, "PII absence", "pii_absence"),
            (2, "License compliance", "license_compliance"),
            (3, "Redistribution compliance", "redistribution_compliance"),
            (4, "Conflict records excluded", "conflict_excluded"),
            (5, "Private data excluded", "private_data_excluded"),
            (6, "Copyright excluded", "copyright_excluded"),
            (7, "Extractive summaries reviewed", "extractive_reviewed"),
            (8, "Dataset card present", "dataset_card_present"),
            (9, "README present", "readme_present"),
            (10, "Manifest present", "manifest_present"),
            (11, "Minimum records (100)", "minimum_records"),
        ]
        
        all_passed = True
        for num, name, key in checks:
            result = results.get(key, {})
            passed = result.get("passed", False)
            status = "✅ PASS" if passed else "❌ FAIL"
            details = result.get("details", "")
            lines.append(f"| {num} | {name} | {status} | {details} |")
            if not passed:
                all_passed = False

        lines.append("")
        overall = "PASS" if all_passed else "FAIL"
        passed_count = sum(1 for r in results.values() if r.get("passed"))
        lines.append(f"**Overall: {overall}** ({passed_count}/11 checks passed)")
        
        return "\n".join(lines)
