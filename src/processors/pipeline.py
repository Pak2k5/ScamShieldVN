"""Processing pipeline orchestrator for ScamShield VN pipeline.

Executes stages in fixed order:
Clean -> Label -> Evidence -> Dedup -> Conflict -> PII -> NamedEntity -> ReviewQueue -> PublicSafety -> TrainingReady
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from src.config.settings import PipelineConfig
from src.models.source import SourceRegistry
from src.processors.cleaner import Cleaner
from src.processors.conflict_detector import ConflictDetector
from src.processors.deduplicator import Deduplicator
from src.processors.evidence_scorer import EvidenceScorer
from src.processors.labeler import Labeler
from src.processors.named_entity_detector import NamedEntityDetector
from src.processors.pii_masker import PIIMasker
from src.processors.public_safety import PublicSafetyComputer
from src.processors.review_queue import ReviewQueueBuilder
from src.processors.training_ready import TrainingReadyComputer


class ProcessingPipeline:
    """Orchestrates the full processing pipeline from raw -> processed.
    
    Pipeline order: Clean -> Label -> Evidence -> Dedup -> Conflict -> 
    PII -> NamedEntity -> ReviewQueue -> PublicSafety -> TrainingReady
    """

    def __init__(self, config: PipelineConfig, registry: SourceRegistry):
        self.config = config
        self.registry = registry
        self.cleaner = Cleaner()
        self.labeler = Labeler()
        self.evidence_scorer = EvidenceScorer()
        self.deduplicator = Deduplicator()
        self.conflict_detector = ConflictDetector()
        self.pii_masker = PIIMasker()
        self.named_entity_detector = NamedEntityDetector()
        self.review_queue_builder = ReviewQueueBuilder()
        self.public_safety = PublicSafetyComputer()
        self.training_ready = TrainingReadyComputer()

        # Build source lookup
        self._source_lookup = {s.source_id: s for s in registry.sources}

    def process(self) -> dict:
        """Run the full processing pipeline.
        
        Returns:
            Dict with keys: records (list), review_queue (list), stats (dict).
        """
        logger.info("Starting processing pipeline...")
        
        # Load raw records from private_raw
        raw_records = self._load_raw_records()
        if not raw_records:
            logger.warning("No raw records found to process.")
            return {"records": [], "review_queue": [], "stats": {}}

        logger.info("Loaded {} raw records.", len(raw_records))

        # Stage 1: Clean & Normalize
        records = self._stage_clean(raw_records)

        # Stage 2: Label
        records = self._stage_label(records)

        # Stage 3: Evidence Scoring
        records = self._stage_evidence(records)

        # Stage 4: Deduplication
        records = self.deduplicator.deduplicate(records)

        # Stage 5: Conflict Detection
        records = self.conflict_detector.detect(records)

        # Stage 6: PII Masking
        records = self._stage_pii(records)

        # Stage 7: Named Entity Detection
        records = self._stage_named_entity(records)

        # Stage 8: Review Queue
        review_queue = self.review_queue_builder.build_queue(records)
        review_record_ids = {entry["record_id"] for entry in review_queue}

        # Stage 9: Public Safety
        for record in records:
            in_queue = record.get("record_id", "") in review_record_ids
            record["public_safe"] = self.public_safety.compute(record, in_review_queue=in_queue)

        # Stage 10: Training Ready
        for record in records:
            in_queue = record.get("record_id", "") in review_record_ids
            record["training_ready"] = self.training_ready.compute(record, in_review_queue=in_queue)

        # Compute stats
        stats = self._compute_stats(records, review_queue)
        logger.info(
            "Processing complete: {} records, {} duplicates removed, {} in review queue, "
            "{} training-ready.",
            stats["total_records"], stats["duplicates_removed"],
            stats["review_queue_count"], stats["training_ready_count"]
        )

        return {"records": records, "review_queue": review_queue, "stats": stats}

    def _load_raw_records(self) -> list[dict]:
        """Load all raw JSONL files from data/private_raw/."""
        raw_dir = Path(self.config.output_dir) / "private_raw"
        records = []
        
        if not raw_dir.exists():
            return records

        for jsonl_file in sorted(raw_dir.glob("*.jsonl")):
            try:
                with open(jsonl_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            record = json.loads(line)
                            records.append(record)
            except Exception as e:
                logger.error("Error reading {}: {}", jsonl_file, e)

        return records

    def _stage_clean(self, records: list[dict]) -> list[dict]:
        """Stage 1: Clean and normalize URLs and text."""
        for record in records:
            # Normalize URL
            url = record.get("url")
            if url:
                try:
                    normalized = self.cleaner.normalize_url(url)
                    record["url"] = normalized
                    record["url_hash"] = self.deduplicator.compute_url_hash(normalized)
                    record["normalization_error"] = False
                    
                    # Compute URL features
                    features = self.cleaner.compute_url_features(normalized)
                    record.update(features)
                except ValueError:
                    record["normalization_error"] = True
                    record["url_hash"] = self.deduplicator.compute_url_hash(url)

            # Normalize text fields
            for field in ["case_summary", "text_sanitized"]:
                text = record.get(field)
                if text:
                    record[field] = self.cleaner.normalize_text(text)

            # Set first_seen/last_seen
            ts = record.get("collection_timestamp")
            if ts and not record.get("first_seen"):
                record["first_seen"] = ts
                record["last_seen"] = ts

        return records

    def _stage_label(self, records: list[dict]) -> list[dict]:
        """Stage 2: Assign labels and scam_types."""
        for record in records:
            source_id = record.get("source_id", "")
            source = self._source_lookup.get(source_id)
            source_type = source.source_type.value if source else ""
            
            label = self.labeler.assign_label(
                record_type=record.get("record_type", ""),
                source_type=source_type,
                threat_type=record.get("threat_type"),
                benign_message_type=record.get("benign_message_type"),
            )
            record["label"] = label.value
            record["source_type"] = source_type

            scam_types = self.labeler.assign_scam_types(
                scam_type_raw=record.get("scam_type"),
                threat_type=record.get("threat_type"),
            )
            record["scam_types"] = scam_types

            # Store redistribution_status from source
            if source:
                record["redistribution_status"] = source.redistribution_status.value
                record["credibility_level"] = source.credibility_level.value

        return records

    def _stage_evidence(self, records: list[dict]) -> list[dict]:
        """Stage 3: Score evidence levels."""
        for record in records:
            evidence = self.evidence_scorer.score(
                source_type=record.get("source_type", ""),
                credibility_level=record.get("credibility_level", "unknown"),
                verification_status=record.get("verification_status"),
                synthetic=record.get("synthetic", False),
            )
            record["evidence_level"] = evidence.value

        return records

    def _stage_pii(self, records: list[dict]) -> list[dict]:
        """Stage 6: Mask PII in text fields."""
        pii_count = 0
        for record in records:
            record = self.pii_masker.mask_record(record)
            if record.get("pii_detected"):
                pii_count += 1
        if pii_count:
            logger.info("PII masking: {} records had PII detected and masked.", pii_count)
        return records

    def _stage_named_entity(self, records: list[dict]) -> list[dict]:
        """Stage 7: Detect named entities."""
        flagged = 0
        for record in records:
            record = self.named_entity_detector.flag_record(record)
            if record.get("possible_named_individual"):
                flagged += 1
        if flagged:
            logger.info("Named entity detection: {} records flagged.", flagged)
        return records

    def _compute_stats(self, records: list[dict], review_queue: list[dict]) -> dict:
        """Compute processing statistics."""
        return {
            "total_records": len(records),
            "duplicates_removed": 0,  # Already logged by deduplicator
            "review_queue_count": len(review_queue),
            "training_ready_count": sum(1 for r in records if r.get("training_ready")),
            "pii_masked_count": sum(1 for r in records if r.get("pii_detected")),
            "conflict_count": sum(1 for r in records if r.get("conflict_status") == "needs_review"),
            "labels": {},
            "evidence_levels": {},
        }
