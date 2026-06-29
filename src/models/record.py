"""
Pydantic data models for pipeline records.

Defines schemas for raw ingested data, processed intermediate records,
public Kaggle-ready output, and benign message records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from src.models.enums import (
    BenignMessageType,
    ConflictStatus,
    EvidenceLevel,
    Label,
    RecordType,
    SummaryMethod,
)


class RawRecord(BaseModel):
    """Schema for raw JSONL records stored in data/private_raw/.

    Represents a single record as ingested from any data source before
    normalization or deduplication. Fields vary by source; most are optional.
    """

    source_id: str
    collection_timestamp: datetime
    record_type: RecordType
    url: Optional[str] = None
    verification_status: Optional[str] = None
    submission_date: Optional[datetime] = None
    threat_type: Optional[str] = None
    date_added: Optional[datetime] = None
    case_summary: Optional[str] = None
    scam_type: Optional[str] = None
    date_reported: Optional[datetime] = None
    source_url: Optional[str] = None
    domain: Optional[str] = None
    status: Optional[str] = None
    date_checked: Optional[datetime] = None
    category: Optional[str] = None
    organization_name: Optional[str] = None
    verification_method: Optional[str] = None
    message_id: Optional[str] = None
    text_sanitized: Optional[str] = None
    benign_message_type: Optional[str] = None
    synthetic: Optional[bool] = None
    source_type_field: Optional[str] = Field(default=None, alias="source_type_raw")
    human_reviewed: Optional[bool] = None
    summary_method: Optional[str] = None
    threat_match: Optional[bool] = None
    positives_count: Optional[int] = None
    total_engines: Optional[int] = None
    raw_content: Optional[str] = None
    raw_article_text: Optional[str] = None


class ProcessedRecord(BaseModel):
    """Schema for processed records stored in data/processed_private/.

    Contains normalized, deduplicated, and enriched data ready for
    labeling, conflict resolution, and downstream export.
    """

    record_id: str
    source_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    record_type: RecordType
    source_labels: Optional[dict[str, str]] = None
    source_evidence_levels: Optional[dict[str, str]] = None
    source_types: Optional[dict[str, str]] = None
    source_threat_types: Optional[dict[str, str]] = None
    url: Optional[str] = None
    url_hash: Optional[str] = None
    normalization_error: bool = False
    domain: Optional[str] = None
    tld: Optional[str] = None
    has_ip_address: bool = False
    has_punycode: bool = False
    has_url_shortener: bool = False
    url_length: Optional[int] = None
    path_length: Optional[int] = None
    query_length: Optional[int] = None
    case_summary: Optional[str] = None
    summary_method: Optional[SummaryMethod] = None
    human_reviewed: bool = False
    text_sanitized: Optional[str] = None
    benign_message_type: Optional[BenignMessageType] = None
    synthetic: Optional[bool] = None
    label: Label = Label.UNKNOWN
    scam_types: list[str] = Field(default_factory=list)
    evidence_level: EvidenceLevel = EvidenceLevel.E
    conflict_status: Optional[ConflictStatus] = None
    conflict_reason: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    pii_detected: bool = False
    pii_redacted: bool = False
    pii_summary: Optional[dict[str, int]] = None
    possible_named_individual: bool = False
    credibility_level: Optional[str] = None
    source_type: Optional[str] = None
    redistribution_status: Optional[str] = None
    threat_match: Optional[bool] = None
    positives_count: Optional[int] = None
    total_engines: Optional[int] = None
    public_safe: bool = False
    training_ready: bool = False
    redistribution_policy_applied: bool = False
    raw_content: Optional[str] = None
    raw_article_text: Optional[str] = None


class PublicRecord(BaseModel):
    """Schema for public Kaggle output in data/public_kaggle/.

    A privacy-safe subset of ProcessedRecord with no raw content,
    suitable for public redistribution and community use.
    """

    record_id: str
    source_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    record_type: RecordType
    url: Optional[str] = None
    domain_hash: Optional[str] = None
    url_length: Optional[int] = None
    path_length: Optional[int] = None
    query_length: Optional[int] = None
    tld: Optional[str] = None
    has_ip_address: bool = False
    has_punycode: bool = False
    has_url_shortener: bool = False
    summary_vi: Optional[str] = None
    source_url: Optional[str] = None
    published_date: Optional[datetime] = None
    text_sanitized: Optional[str] = None
    benign_message_type: Optional[str] = None
    synthetic: Optional[bool] = None
    summary_method: Optional[str] = None
    human_reviewed: bool = False
    label: str
    scam_types: list[str] = Field(default_factory=list)
    risk_signals: list[str] = Field(default_factory=list)
    evidence_level: str
    redistribution_status: str
    redistribution_policy_applied: bool = False
    training_ready: bool = False
    source_type: Optional[str] = None
    credibility_level: Optional[str] = None


class BenignMessageRecord(BaseModel):
    """Schema for benign (non-scam) message records.

    Used to represent verified safe messages for training balanced
    classifiers and reducing false positive rates.
    """

    message_id: str
    text_sanitized: str
    benign_message_type: BenignMessageType
    synthetic: bool
    source_type: str
    human_reviewed: bool
    source_ids: list[str]
    evidence_level: EvidenceLevel
    collected_at: datetime
