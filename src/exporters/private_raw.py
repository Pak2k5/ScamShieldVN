"""Private raw JSONL exporter for ScamShield VN pipeline."""

import json
from datetime import datetime
from pathlib import Path

from loguru import logger

from src.models.record import RawRecord


class PrivateRawExporter:
    """Writes raw collected records to data/private_raw/ as JSONL.
    
    One file per source, named: {source_id}_{YYYYMMDD}.jsonl
    Also generates PRIVATE_DATA_WARNING.md in the output directory.
    """

    def __init__(self, output_dir: str = "./data"):
        self.output_dir = Path(output_dir) / "private_raw"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, records: list[RawRecord], source_id: str) -> Path:
        """Write records to a JSONL file for the given source.
        
        Args:
            records: List of raw records to export.
            source_id: Source identifier for file naming.
            
        Returns:
            Path to the written JSONL file.
        """
        if not records:
            logger.info("No records to export for source '{}'.", source_id)
            return self.output_dir

        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"{source_id}_{date_str}.jsonl"
        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            for record in records:
                line = record.model_dump_json(exclude_none=True)
                f.write(line + "\n")

        logger.info("Exported {} records to {}", len(records), filepath)
        return filepath

    def write_warning_file(self) -> None:
        """Generate PRIVATE_DATA_WARNING.md in private_raw directory."""
        warning_path = self.output_dir / "PRIVATE_DATA_WARNING.md"
        if not warning_path.exists():
            warning_path.write_text(
                "# ⚠️ PRIVATE DATA - DO NOT SHARE\n\n"
                "This directory contains **unmasked raw data** including potentially sensitive information:\n\n"
                "- Full URLs from restricted sources\n"
                "- Unmasked phone numbers, bank accounts, national IDs\n"
                "- Raw article text with copyright\n"
                "- Personal names and addresses\n\n"
                "## Rules\n\n"
                "1. **NEVER** commit this directory to version control\n"
                "2. **NEVER** upload to Kaggle, GitHub, or any public platform\n"
                "3. **NEVER** share with unauthorized persons\n"
                "4. Use only for internal research and pipeline processing\n\n"
                "The `.gitignore` should exclude this entire directory.\n"
                "If you see this file in a Git repo, something is wrong.\n",
                encoding="utf-8",
            )
            logger.debug("Created PRIVATE_DATA_WARNING.md")
