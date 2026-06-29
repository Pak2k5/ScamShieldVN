"""LICENSE_NOTES.md generator for ScamShield VN pipeline."""

from pathlib import Path
from loguru import logger

from src.models.source import SourceRegistry


class LicenseNotesGenerator:
    """Generates LICENSE_NOTES.md documenting per-source licensing."""

    def generate(self, registry: SourceRegistry, output_dir: str = "./data") -> Path:
        """Generate LICENSE_NOTES.md in data/public_kaggle/."""
        path = Path(output_dir) / "public_kaggle" / "LICENSE_NOTES.md"
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# License Notes",
            "",
            "This document describes the licensing and redistribution terms for each data source used in the ScamShield VN dataset.",
            "",
            "## Summary",
            "",
            "| Source ID | Source Name | Redistribution | License Note |",
            "|-----------|-------------|----------------|--------------|",
        ]

        for source in registry.sources:
            lines.append(
                f"| {source.source_id} | {source.source_name} | "
                f"{source.redistribution_status.value} | {source.license_note} |"
            )

        lines.extend([
            "",
            "## Redistribution Policy",
            "",
            "- **allowed**: Full data may be included in public output.",
            "- **prohibited**: Only derived features (domain hash, URL length, TLD) are public. Raw URLs/content excluded.",
            "- **unknown**: Treated as prohibited for safety. Only derived features exported publicly.",
            "",
            "## Dataset License",
            "",
            "The curated portions of this dataset (taxonomy, benign domains, benign messages) are released under CC-BY-4.0.",
            "Third-party data retains its original license. See individual source entries above.",
            "",
            "## Important Notes",
            "",
            "- Private raw data (data/private_raw/) is NEVER published",
            "- PII is masked in all public output",
            "- This dataset does not make legal conclusions about individuals or organizations",
        ])

        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Generated LICENSE_NOTES.md in public_kaggle/")
        return path
