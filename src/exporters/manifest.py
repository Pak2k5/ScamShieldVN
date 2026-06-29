"""Data manifest generator for ScamShield VN pipeline."""

import hashlib
import json
from datetime import datetime
from pathlib import Path

from loguru import logger


class ManifestGenerator:
    """Generates data_manifest.json with checksums and versioning."""

    def generate(self, output_dir: str = "./data", dataset_version: str = "0.1.0",
                 stats: dict = None) -> Path:
        """Generate data_manifest.json in data/public_kaggle/."""
        public_dir = Path(output_dir) / "public_kaggle"
        public_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = public_dir / "data_manifest.json"

        # Compute file checksums
        files = []
        for file_path in sorted(public_dir.iterdir()):
            if file_path.name == "data_manifest.json":
                continue
            if file_path.is_file():
                file_info = {
                    "file_name": file_path.name,
                    "file_size_bytes": file_path.stat().st_size,
                    "sha256_checksum": self._compute_sha256(file_path),
                    "row_count": self._count_rows(file_path),
                }
                files.append(file_info)

        manifest = {
            "dataset_version": dataset_version,
            "build_date": datetime.now().isoformat(),
            "pipeline_version": "0.1.0",
            "total_record_count": stats.get("total_records", 0) if stats else 0,
            "training_ready_count": stats.get("training_ready_count", 0) if stats else 0,
            "files": files,
            "source_snapshot_date": datetime.now().strftime("%Y-%m-%d"),
            "sources_used": stats.get("sources_used", []) if stats else [],
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        logger.info("Generated data_manifest.json (version={}, {} files)", dataset_version, len(files))
        return manifest_path

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA-256 checksum for a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _count_rows(self, file_path: Path) -> int:
        """Estimate row count for a file."""
        suffix = file_path.suffix.lower()
        try:
            if suffix == ".jsonl":
                with open(file_path, "r", encoding="utf-8") as f:
                    return sum(1 for line in f if line.strip())
            elif suffix == ".csv":
                with open(file_path, "r", encoding="utf-8") as f:
                    return sum(1 for _ in f) - 1  # Minus header
            else:
                return 0
        except Exception:
            return 0
