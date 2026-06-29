"""Review Queue models for records requiring human review."""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

from src.models.enums import EvidenceLevel, Label, ConflictStatus, RequiresAction


class ReviewQueueRecord(BaseModel):
    """A record in the review queue awaiting human review."""
    
    record_id: str
    review_reason: list[str]
    source_ids: list[str]
    label: Label
    evidence_level: EvidenceLevel
    conflict_status: Optional[ConflictStatus] = None
    pii_detected: bool = False
    requires_action: RequiresAction = RequiresAction.APPROVE
    reviewer_assigned: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
