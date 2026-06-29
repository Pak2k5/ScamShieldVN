"""Data Manifest models for dataset versioning and integrity."""

from __future__ import annotations
from pydantic import BaseModel


class ManifestFile(BaseModel):
    """Metadata for a single exported file in the manifest."""
    
    file_name: str
    row_count: int
    file_size_bytes: int
    sha256_checksum: str


class DataManifest(BaseModel):
    """Dataset manifest for versioning and integrity verification."""
    
    dataset_version: str
    build_date: str  # ISO 8601
    pipeline_version: str
    total_record_count: int
    training_ready_count: int
    files: list[ManifestFile]
    source_snapshot_date: str  # ISO 8601
    sources_used: list[str]  # source_ids
