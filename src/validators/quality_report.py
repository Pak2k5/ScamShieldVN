"""Data quality report generator."""

from pathlib import Path
import json
from collections import Counter
from loguru import logger


class QualityReportGenerator:
    """Generates Markdown quality report for the dataset."""

    def generate(self, output_dir: str = "./data") -> Path:
        """Generate data quality report in reports/ directory."""
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / "data_quality_report.md"

        # Load public records
        public_path = Path(output_dir) / "public_kaggle" / "scamshield_vn_public.jsonl"
        records = []
        if public_path.exists():
            with open(public_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))

        # Compute stats
        total = len(records)
        label_counts = Counter(r.get("label", "unknown") for r in records)
        evidence_counts = Counter(r.get("evidence_level", "e") for r in records)
        training_ready = sum(1 for r in records if r.get("training_ready"))
        not_ready = total - training_ready

        lines = [
            "# Data Quality Report\n",
            f"**Generated**: {Path(output_dir)}\n",
            "## Summary\n",
            f"- **Total public records**: {total}",
            f"- **Training-ready**: {training_ready}",
            f"- **Not training-ready**: {not_ready}",
            "",
            "## Records by Label\n",
            "| Label | Count |",
            "|-------|-------|",
        ]
        for label, count in label_counts.most_common():
            lines.append(f"| {label} | {count} |")

        lines.extend([
            "",
            "## Records by Evidence Level\n",
            "| Level | Count |",
            "|-------|-------|",
        ])
        for level in ["a", "b", "c", "d", "e"]:
            lines.append(f"| {level.upper()} | {evidence_counts.get(level, 0)} |")

        lines.extend([
            "",
            "## Training Readiness\n",
            f"- Training-ready: {training_ready} ({training_ready/total*100:.1f}%)" if total else "- No records",
            f"- Not ready: {not_ready} ({not_ready/total*100:.1f}%)" if total else "",
            "",
            "## Data Quality Warnings\n",
            "- This dataset does NOT make legal conclusions about individuals or organizations.",
            "- Evidence level D/E records are excluded from training-ready output.",
            "- PII masking is regex-based and may have edge-case false negatives.",
            "- Vietnamese sources are limited by robots.txt/ToS compliance.",
        ])

        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Generated data quality report at {}", report_path)
        return report_path
