"""Processed private exporter for ScamShield VN pipeline.

Writes cleaned, labeled data to data/processed_private/ in CSV, JSONL, and Parquet formats.
"""

import csv
import json
from pathlib import Path

import pandas as pd
from loguru import logger


class ProcessedPrivateExporter:
    """Exports processed data to CSV, JSONL, and Parquet in data/processed_private/."""

    def __init__(self, output_dir: str = "./data"):
        self.output_dir = Path(output_dir) / "processed_private"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, records: list[dict]) -> list[Path]:
        """Export records in all formats. Returns list of written file paths."""
        if not records:
            logger.warning("No records to export.")
            return []

        written = []

        # JSONL
        jsonl_path = self.output_dir / "scamshield_vn_processed.jsonl"
        self._write_jsonl(records, jsonl_path)
        written.append(jsonl_path)

        # CSV
        csv_path = self.output_dir / "scamshield_vn_processed.csv"
        self._write_csv(records, csv_path)
        written.append(csv_path)

        # Parquet
        parquet_path = self.output_dir / "scamshield_vn_processed.parquet"
        self._write_parquet(records, parquet_path)
        written.append(parquet_path)

        logger.info("Exported {} records to {} files in {}.", len(records), len(written), self.output_dir)
        return written

    def _write_jsonl(self, records: list[dict], path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")

    def _write_csv(self, records: list[dict], path: Path) -> None:
        if not records:
            return
        df = pd.DataFrame(records)
        # Convert list columns to pipe-separated strings for CSV
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else x)
        df.to_csv(path, index=False, encoding="utf-8")

    def _write_parquet(self, records: list[dict], path: Path) -> None:
        df = pd.DataFrame(records)
        # Convert non-serializable types for parquet
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else x)
        df.to_parquet(path, index=False, engine="pyarrow")
