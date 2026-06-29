"""Public Kaggle exporter for ScamShield VN pipeline.

Writes sanitized public data to data/public_kaggle/ in CSV, JSONL, and Parquet formats.
"""

import json
from pathlib import Path

import pandas as pd
from loguru import logger


class PublicKaggleExporter:
    """Exports public-safe data to CSV, JSONL, and Parquet in data/public_kaggle/."""

    def __init__(self, output_dir: str = "./data"):
        self.output_dir = Path(output_dir) / "public_kaggle"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(self, records: list[dict]) -> list[Path]:
        """Export public records in all formats."""
        if not records:
            logger.warning("No public records to export.")
            return []

        written = []

        # JSONL
        jsonl_path = self.output_dir / "scamshield_vn_public.jsonl"
        self._write_jsonl(records, jsonl_path)
        written.append(jsonl_path)

        # CSV
        csv_path = self.output_dir / "scamshield_vn_public.csv"
        self._write_csv(records, csv_path)
        written.append(csv_path)

        # Parquet
        parquet_path = self.output_dir / "scamshield_vn_public.parquet"
        self._write_parquet(records, parquet_path)
        written.append(parquet_path)

        logger.info("Exported {} public records to {} files in {}.", len(records), len(written), self.output_dir)
        return written

    def _write_jsonl(self, records: list[dict], path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, default=str, ensure_ascii=False) + "\n")

    def _write_csv(self, records: list[dict], path: Path) -> None:
        df = pd.DataFrame(records)
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else x)
        df.to_csv(path, index=False, encoding="utf-8")

    def _write_parquet(self, records: list[dict], path: Path) -> None:
        df = pd.DataFrame(records)
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else x)
        df.to_parquet(path, index=False, engine="pyarrow")
