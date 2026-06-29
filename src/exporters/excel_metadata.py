"""Excel metadata exporter for ScamShield VN pipeline.

Generates .xlsx files for smaller metadata and reference files only.
Main dataset is exported as CSV/JSONL/Parquet (not Excel).
"""

import json
from pathlib import Path

import pandas as pd
from loguru import logger


class ExcelMetadataExporter:
    """Exports metadata and sample files to Excel format in data/public_kaggle/."""

    def __init__(self, output_dir: str = "./data"):
        self.output_dir = Path(output_dir) / "public_kaggle"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_source_registry(self, sources: list[dict]) -> Path:
        """Export source registry to Excel."""
        path = self.output_dir / "source_registry.xlsx"
        df = pd.DataFrame(sources)
        df.to_excel(path, index=False, engine="openpyxl")
        logger.info("Written source_registry.xlsx ({} sources)", len(sources))
        return path

    def export_taxonomy(self, taxonomy: list[dict]) -> Path:
        """Export scam taxonomy to Excel."""
        path = self.output_dir / "scam_taxonomy.xlsx"
        df = pd.DataFrame(taxonomy)
        # Convert list columns
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, list)).any():
                df[col] = df[col].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        df.to_excel(path, index=False, engine="openpyxl")
        logger.info("Written scam_taxonomy.xlsx ({} types)", len(taxonomy))
        return path

    def export_sample_records(self, records: list[dict], max_rows: int = 1000) -> Path:
        """Export a sample of the main dataset to Excel (max 1000 rows)."""
        path = self.output_dir / "sample_records.xlsx"
        sample = records[:max_rows]
        df = pd.DataFrame(sample)
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df[col] = df[col].apply(lambda x: json.dumps(x, ensure_ascii=False) if isinstance(x, (list, dict)) else x)
        df.to_excel(path, index=False, engine="openpyxl")
        logger.info("Written sample_records.xlsx ({} rows)", len(sample))
        return path

    def export_review_queue_summary(self, review_queue: list[dict]) -> Path:
        """Export review queue summary to Excel."""
        path = self.output_dir / "review_queue_summary.xlsx"
        
        # Create summary stats
        from collections import Counter
        reason_counts = Counter()
        for entry in review_queue:
            for reason in entry.get("review_reason", []):
                reason_counts[reason] += 1
        
        summary_data = [
            {"metric": "total_pending_review", "value": len(review_queue)},
        ]
        for reason, count in reason_counts.most_common():
            summary_data.append({"metric": f"reason_{reason}", "value": count})
        
        df = pd.DataFrame(summary_data)
        df.to_excel(path, index=False, engine="openpyxl")
        logger.info("Written review_queue_summary.xlsx")
        return path
