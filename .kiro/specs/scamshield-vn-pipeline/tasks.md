# Implementation Plan: ScamShield VN Pipeline

## Overview

This implementation plan is organized by milestones, starting with Milestone 1 (Foundation). Each milestone builds incrementally on the previous one. The pipeline is implemented in Python using Pydantic for validation, loguru for logging, Hypothesis for property-based testing, and standard CLI tools (argparse). The processing pipeline follows the fixed order: Clean → Label → Evidence → Dedup → Conflict → PII → NamedEntity → ReviewQueue → PublicSafety → TrainingReady.

## Tasks

### Milestone 1: Foundation

- [x] 1. Set up project structure and dependencies
  - [x] 1.1 Create project scaffolding with pyproject.toml and requirements.txt
    - Create `pyproject.toml` with project metadata, Python >=3.11 requirement, and dependencies: pydantic, loguru, python-dotenv, pyyaml, tenacity, httpx, hypothesis, pytest
    - Create `requirements.txt` pinning exact versions of all dependencies
    - Create directory structure: `src/`, `src/config/`, `src/models/`, `src/collectors/`, `src/processors/`, `src/exporters/`, `src/validators/`, `src/utils/`, `tests/`, `tests/unit/`, `tests/property/`, `tests/integration/`, `config/`, `data/`, `reports/`
    - Create `__init__.py` files in all Python package directories
    - _Requirements: 11.1, 13.4_

  - [x] 1.2 Create .gitignore and .env.example
    - Create `.gitignore` excluding: `data/private_raw/`, `data/processed_private/`, `.env`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `reports/*.log`, `*.egg-info/`
    - Create `.env.example` with placeholder keys: `SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY=`, `SCAMSHIELD_VIRUSTOTAL_KEY=`, `SCAMSHIELD_PHISHTANK_KEY=`
    - _Requirements: 13.1, 14.1, 14.6_

  - [x] 1.3 Create configuration YAML files
    - Create `config/sources.yaml` with initial source definitions for all planned collectors (phishtank_verified, openphish_feed, urlhaus_malware, safe_browsing, virustotal, vietnamese_official, tin_nhiem_mang, tranco_top1000, benign_domains_vn, benign_messages)
    - Create `config/pipeline.yaml` with defaults: output_dir=./data, rate_limit_rps=1.0, max_retries=3, backoff_base=2, backoff_max=30, timeout=30
    - Create `config/taxonomy_seed.yaml` with 18 Vietnamese scam categories
    - Create `config/vietnamese_sources.yaml` with curated seed URLs for Vietnamese official sources
    - _Requirements: 1.1, 4.1, 4.5, 13.4_

- [ ] 2. Implement Pydantic data models
  - [x] 2.1 Create enum definitions in src/models/enums.py
    - Implement `SourceType`, `CredibilityLevel`, `AccessMethod`, `RedistributionStatus` enums as `str, Enum` subclasses
    - Implement `EvidenceLevel` enum (A, B, C, D, E)
    - Implement `RecordType` enum (url, case, domain, message)
    - Implement `ConflictStatus` enum (needs_review, resolved)
    - Implement `BenignMessageType` enum (otp_warning, delivery_notification, bank_education, promotion, system_notification, other)
    - Implement `SummaryMethod` enum (manual, extractive, abstractive, rule_based)
    - Implement `RequiresAction` enum (approve, reject, edit, escalate)
    - _Requirements: 1.5, 1.6, 1.7, 1.8, 4.5, 5.7_

  - [ ] 2.2 Create source registry model in src/models/source.py
    - Implement `SourceEntry` Pydantic BaseModel with all required fields: source_id, source_name, source_url (HttpUrl), source_type, credibility_level, license_note, access_method, redistribution_status
    - Add optional fields: rate_limit_rps (default 1.0), requires_api_key (default False), enabled (default True)
    - Implement `SourceRegistry` model containing `sources: list[SourceEntry]` with a validator for source_id uniqueness
    - _Requirements: 1.3, 1.4, 1.9, 1.10_

  - [ ] 2.3 Create record models in src/models/record.py
    - Implement `RawRecord` Pydantic model matching the design schema (source_id, collection_timestamp, record_type, optional URL/case/domain/message/enrichment fields, raw_content, raw_article_text)
    - Implement `ProcessedRecord` Pydantic model with all fields from design (record_id UUID v4, source_ids list, classification fields, PII fields, conflict fields, training_ready, public_safe, etc.)
    - Implement `PublicRecord` Pydantic model (subset of ProcessedRecord without raw_content, raw_article_text, with conditional URL/domain_hash)
    - Implement `BenignMessageRecord` Pydantic model
    - _Requirements: 3.1, 3.2, 3.3, 5.7, 6.4, 6.5, 7.4, 8.1, 9.5, 16.1_

  - [ ] 2.4 Create review and manifest models
    - Implement `ReviewQueueRecord` in `src/models/review.py` with fields: record_id, review_reason (list), source_ids, label, evidence_level, conflict_status, pii_detected, requires_action, reviewer_assigned, reviewed_by, reviewed_at, review_notes
    - Implement `ManifestFile` and `DataManifest` in `src/models/manifest.py` with fields: dataset_version, build_date, pipeline_version, total_record_count, training_ready_count, files list, source_snapshot_date, sources_used
    - _Requirements: 15.3, 17.1_

- [ ] 3. Implement configuration loaders
  - [ ] 3.1 Implement source registry loader in src/config/registry.py
    - Load and parse `config/sources.yaml` using PyYAML
    - Validate the parsed YAML against `SourceRegistry` Pydantic model
    - Raise `ConfigurationError` with file path and parsing failure details if YAML is malformed
    - Raise `ValidationError` identifying missing fields, invalid enum values, and duplicate source_ids with position index
    - Accept optional custom path via `--config` CLI flag
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.9, 1.10, 11.8_

  - [ ] 3.2 Implement pipeline config loader in src/config/settings.py
    - Load `config/pipeline.yaml` and merge with defaults
    - Expose typed `PipelineConfig` Pydantic model with fields: output_dir, rate_limit_rps, max_retries, backoff_base, backoff_max, timeout
    - If file does not exist, use all defaults and log informational message
    - _Requirements: 13.4, 13.5_

  - [ ] 3.3 Implement environment variable loader in src/config/env.py
    - Load `.env` file using python-dotenv
    - Read API keys: SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY, SCAMSHIELD_VIRUSTOTAL_KEY, SCAMSHIELD_PHISHTANK_KEY
    - Environment variables take precedence over .env values
    - Treat empty/whitespace-only values as not configured; log warning for affected service
    - _Requirements: 13.1, 13.2, 13.3_

- [ ] 4. Implement logging and CLI
  - [ ] 4.1 Implement logging setup in src/main.py
    - Configure loguru with console handler (human-readable, INFO default) and JSON file handler (DEBUG level)
    - Log file named `pipeline_YYYYMMDD_HHMMSS.log` in reports/ directory
    - Support `--verbose` flag to set console to DEBUG
    - Structured JSON log events with fields: timestamp, level, event_type, source_id, records_fetched, duration_seconds, error_message
    - _Requirements: 12.1, 12.2, 12.3, 12.5_

  - [ ] 4.2 Implement CLI argument parser in src/cli.py
    - Build argparse parser with subcommands: collect, process, export, validate, run
    - Global options: `--config PATH`, `--output-dir PATH`, `--verbose`
    - collect options: `--source SOURCE_ID`
    - export options: `--target {kaggle,all}`
    - Print usage message and exit code 2 on invalid arguments
    - _Requirements: 11.1, 11.2, 11.3, 11.5, 11.8, 11.9, 11.10, 11.12_

  - [ ] 4.3 Implement subcommand routing in src/main.py
    - Wire CLI parser to dispatch: collect → collection phase, process → processing phase, export → export phase, validate → validation phase, run → all in sequence
    - For `run`: stop execution and report failed step on fatal error
    - Exit codes: 0 success, 1 fatal error, 2 invalid arguments
    - _Requirements: 11.4, 11.6, 11.7, 11.11_

- [ ] 5. Property tests for Milestone 1 (Foundation)
  - [ ]* 5.1 Write property test for source registry validation completeness
    - **Property 1: Source Registry Validation Completeness**
    - Use Hypothesis to generate random source entry dictionaries; verify validation passes iff all required fields present with valid enum values; verify validation fails with error identifying the specific invalid field when requirements not met
    - File: `tests/property/test_pbt_registry.py`
    - **Validates: Requirements 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9**

  - [ ]* 5.2 Write property test for source ID uniqueness enforcement
    - **Property 2: Source ID Uniqueness Enforcement**
    - Use Hypothesis to generate lists of source entries with duplicate source_ids; verify registry validation rejects with error identifying the duplicate
    - File: `tests/property/test_pbt_registry.py`
    - **Validates: Requirements 1.10**

- [ ] 6. Checkpoint - Milestone 1 Foundation complete
  - Ensure all tests pass, ask the user if questions arise.
  - Verify: pyproject.toml installs cleanly, config files parse correctly, CLI prints help and routes subcommands, logging outputs to console and file

### Milestone 2: Collection

- [ ] 7. Implement shared HTTP infrastructure
  - [ ] 7.1 Implement shared HTTP client in src/utils/http_client.py
    - Create `HttpClient` class wrapping httpx.AsyncClient with configurable timeout (default 30s)
    - Implement rate limiting per domain (default 1 req/s, configurable via source entry)
    - Integrate tenacity retry decorator: 3 retries, exponential backoff (2s base, 30s max), retry on HTTP 5xx/ConnectionError/TimeoutError
    - Skip without retry on HTTP 4xx, log warning with source_id and status code
    - Log retry attempts with source_id and attempt number
    - _Requirements: 2.7, 3.6, 3.7, 3.8_

  - [ ] 7.2 Implement robots.txt checker in src/collectors/robots_checker.py
    - Create `RobotsChecker` class with domain-level caching
    - Fetch and parse robots.txt with 10-second timeout
    - Return `is_allowed(url, user_agent="*")` → bool
    - On timeout or fetch failure: treat as disallowed, log warning
    - _Requirements: 2.1, 2.2, 2.3_

- [ ] 8. Implement base collector and threat feed collectors
  - [ ] 8.1 Implement BaseCollector abstract class in src/collectors/base.py
    - Define abstract `collect() -> list[RawRecord]` method
    - Implement `pre_collect_checks()` using RobotsChecker for web sources
    - Accept `SourceEntry`, `PipelineConfig`, and `HttpClient` in constructor
    - _Requirements: 2.1, 2.4, 2.5_

  - [ ] 8.2 Implement PhishTank collector in src/collectors/phishtank.py
    - Extend BaseCollector, implement `collect()` to retrieve verified phishing URLs from PhishTank API
    - Store records with: source_id, url, verification_status, submission_date
    - Handle API key (optional from env) for higher rate limits
    - Log empty results as informational, not error
    - _Requirements: 3.1, 3.7_

  - [ ] 8.3 Implement OpenPhish collector in src/collectors/openphish.py
    - Extend BaseCollector, implement `collect()` to retrieve current phishing URL feed
    - Store records with: source_id, url, collection_timestamp
    - _Requirements: 3.2_

  - [ ] 8.4 Implement URLhaus collector in src/collectors/urlhaus.py
    - Extend BaseCollector, implement `collect()` to retrieve malware URLs via API/CSV
    - Store records with: source_id, url, threat_type, date_added
    - _Requirements: 3.3_

- [ ] 9. Implement enrichment and Vietnamese source collectors
  - [ ] 9.1 Implement Safe Browsing enricher in src/collectors/safe_browsing.py
    - Batch-check URLs against Google Safe Browsing API (up to 500 per request)
    - Store threat_match boolean and threat type as enrichment fields
    - Skip if API key not configured (log INFO)
    - _Requirements: 3.4, 13.2_

  - [ ] 9.2 Implement VirusTotal enricher in src/collectors/virustotal.py
    - Query individual URLs for detection statistics (1 URL/request, rate limited)
    - Store positives_count and total_engines as enrichment fields
    - Skip if API key not configured (log INFO)
    - _Requirements: 3.5, 13.2_

  - [ ] 9.3 Implement Vietnamese official source collector in src/collectors/vietnamese_official.py
    - Load seed URLs from `config/vietnamese_sources.yaml`
    - Collect case metadata: source_id, case_summary (max 120 words for public), scam_type, date_reported, source_url
    - Include summary_method and human_reviewed fields
    - Do NOT store full copyrighted article text; only metadata and paraphrased summary
    - Respect robots.txt and rate limits per domain
    - _Requirements: 4.2, 4.3, 4.6, 4.7, 4.8, 4.9_

  - [ ] 9.4 Implement Tín Nhiệm Mạng collector in src/collectors/tin_nhiem_mang.py
    - Collect domain status records: source_id, domain, status (scam/phishing/malware/suspicious/unverified), date_checked
    - _Requirements: 4.4_

- [ ] 10. Implement benign data collectors
  - [ ] 10.1 Implement Tranco List collector in src/collectors/tranco.py
    - Download top 1000 ranked domains from Tranco List
    - Store: source_id, domain, category="international", verification_method="tranco_ranking"
    - Retry up to 3 times with exponential backoff if unavailable
    - _Requirements: 5.2, 5.5_

  - [ ] 10.2 Implement benign domains collector in src/collectors/benign_domains.py
    - Load curated Vietnamese benign domain list from config
    - Categories: banking, e-wallet, e-commerce, logistics, telecommunications, government (min 5 per category)
    - Store: source_id, domain, category, organization_name, verification_method="manual_curated"
    - _Requirements: 5.1, 5.3_

  - [ ] 10.3 Implement benign messages collector in src/collectors/benign_messages.py
    - Produce benign message records: message_id, text_sanitized, benign_message_type, synthetic, source_type, human_reviewed, source_ids, evidence_level, collected_at
    - Cap synthetic messages at evidence_level B maximum
    - _Requirements: 5.6, 5.7, 5.8_

- [ ] 11. Implement private raw exporter in src/exporters/private_raw.py
  - Write raw JSONL to data/private_raw/ (one file per source, named `{source_id}_{YYYYMMDD}.jsonl`)
  - Generate PRIVATE_DATA_WARNING.md in data/private_raw/
  - _Requirements: 9.1, 14.2_

- [ ] 12. Checkpoint - Milestone 2 Collection complete
  - Ensure all tests pass, ask the user if questions arise.
  - Verify: all collectors instantiate and produce valid RawRecord objects, HTTP client retries correctly, robots.txt checker works, private_raw JSONL files are written

### Milestone 3: Processing Pipeline

- [ ] 13. Implement cleaning and normalization
  - [ ] 13.1 Implement URL and text normalizer in src/processors/cleaner.py
    - `normalize_url()`: lowercase scheme+domain, remove trailing slash, remove default ports (80/443), sort query params alphabetically
    - `normalize_text()`: NFC normalize, strip Cc/Cf control chars (keep \n\t\r), collapse whitespace, preserve Vietnamese diacritical marks
    - `clean_record()`: apply normalizations, set normalization_error flag on URL parse failure, retain original URL
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ]* 13.2 Write property test for URL normalization idempotence
    - **Property 4: URL Normalization Idempotence**
    - Use Hypothesis to generate valid URL strings; verify normalize(normalize(url)) == normalize(url); verify scheme, domain identity, path, and query params preserved
    - File: `tests/property/test_pbt_cleaner.py`
    - **Validates: Requirements 6.1**

  - [ ]* 13.3 Write property test for text normalization preserving Vietnamese
    - **Property 5: Text Normalization Preserves Vietnamese and is Idempotent**
    - Use Hypothesis to generate Unicode text with Vietnamese diacritics; verify all Vietnamese characters preserved; verify idempotence
    - File: `tests/property/test_pbt_cleaner.py`
    - **Validates: Requirements 6.3**

- [ ] 14. Implement labeling and evidence scoring
  - [ ] 14.1 Implement labeler in src/processors/labeler.py
    - Assign exactly one primary label from: phishing_url, malware_url, scam_case, scam_pattern, suspicious, community_reported_unverified, benign_url, benign_message, unknown
    - Assign 0-5 scam_type values from Vietnamese taxonomy (default to "other" if value not in taxonomy)
    - Strip personal names from label fields
    - Default to "unknown" with evidence_level E if insufficient metadata
    - _Requirements: 8.1, 8.9, 8.10, 8.11, 4.6_

  - [ ]* 14.2 Write property test for labeling invariants
    - **Property 8: Labeling Invariants**
    - Use Hypothesis to generate records; verify exactly one primary label assigned from valid set; verify scam_types has 0-5 values all from taxonomy or "other"
    - File: `tests/property/test_pbt_labeler.py`
    - **Validates: Requirements 8.1, 8.9, 4.6**

  - [ ] 14.3 Implement evidence scorer in src/processors/evidence_scorer.py
    - Score evidence_level A-E based on source metadata and credibility rules
    - A: official/threat_feed + confirmed verification
    - B: high credibility OR 2+ corroborating sources
    - C: community_report with URL/screenshot/date
    - D: low credibility, no corroboration
    - E: no source_id or unknown credibility
    - Cap synthetic benign messages at B maximum
    - _Requirements: 8.4, 8.5, 8.6, 8.7, 8.8, 5.8_

  - [ ]* 14.4 Write property test for evidence level scoring determinism
    - **Property 9: Evidence Level Scoring Determinism**
    - Use Hypothesis to generate records with various source metadata; verify deterministic assignment based on rules; verify synthetic messages never exceed B
    - File: `tests/property/test_pbt_evidence.py`
    - **Validates: Requirements 8.4, 8.5, 8.6, 8.7, 8.8, 5.8**

- [ ] 15. Implement deduplication and conflict detection
  - [ ] 15.1 Implement deduplicator in src/processors/deduplicator.py
    - Compute SHA-256 hash of normalized URL for dedup key
    - Group by url_hash, keep record with highest evidence_level (A>B>C>D>E); tie-break by earliest first_seen
    - Merge source metadata on collision: source_ids, source_labels, source_evidence_levels, source_types, source_threat_types
    - Preserve first_seen (earliest) and last_seen (latest) across duplicates
    - Assign UUID v4 record_id to each deduplicated output
    - _Requirements: 6.4, 6.5_

  - [ ]* 15.2 Write property test for deduplication correctness
    - **Property 6: Deduplication Correctness**
    - Use Hypothesis to generate sets of records with shared URL hashes; verify exactly one retained per hash group; verify highest evidence kept; verify source_ids merged; verify UUID v4 assigned
    - File: `tests/property/test_pbt_deduplication.py`
    - **Validates: Requirements 6.4, 6.5**

  - [ ] 15.3 Implement conflict detector in src/processors/conflict_detector.py
    - Detect records appearing in both benign_reference AND threat_feed/official_government sources (using merged source_types from dedup)
    - Also detect where source_labels contains both benign_url and malicious labels
    - Set conflict_status="needs_review", populate conflict_reason with contradicting source details
    - _Requirements: 8.2, 8.3_

  - [ ]* 15.4 Write property test for conflict detection completeness
    - **Property 10: Conflict Detection Completeness**
    - Use Hypothesis to generate records with mixed benign/malicious source metadata; verify conflict_status set correctly; verify such records excluded from training-ready output
    - File: `tests/property/test_pbt_export.py`
    - **Validates: Requirements 8.2, 9.11**

- [ ] 16. Implement PII masking and named entity detection
  - [ ] 16.1 Implement PII masker in src/processors/pii_masker.py
    - Load regex patterns from config/pii_patterns.yaml
    - Scan free-text fields (case_summary, raw_content, text_sanitized, string fields)
    - Detect: Vietnamese phone numbers, bank account numbers, national IDs (CMND 9-digit, CCCD 12-digit), personal emails, physical addresses, OTP codes, passwords, payment card numbers (Luhn validation)
    - Replace with type-specific tokens: [PHONE_REDACTED], [BANK_ACCOUNT_REDACTED], [EMAIL_REDACTED], [ID_REDACTED], [ADDRESS_REDACTED], [OTP_REDACTED], [PASSWORD_REDACTED], [CARD_REDACTED]
    - Set pii_detected=True, populate pii_summary counts
    - On error: add to review queue with reason "pii_masking_error"
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [ ]* 16.2 Write property test for PII masking completeness
    - **Property 7: PII Masking Completeness**
    - Use Hypothesis to generate text with embedded Vietnamese phone numbers, bank accounts, IDs, emails, OTPs, passwords, card numbers; verify output contains redaction token and NOT the original PII; verify pii_detected=True and pii_summary counts accurate
    - File: `tests/property/test_pbt_pii_masker.py`
    - **Validates: Requirements 7.1, 7.2, 7.4**

  - [ ] 16.3 Implement named entity detector in src/processors/named_entity_detector.py
    - Detect Vietnamese personal name patterns: anh/chị/ông/bà + Capitalized_Name, "đứng tên [Name]", "[Name] lừa đảo", known Vietnamese name patterns (2-4 syllables, capitalized)
    - Set possible_named_individual=True on detection
    - Flag for review queue with reason "possible_named_individual"
    - _Requirements: 8.10, 15.2_

  - [ ]* 16.4 Write property test for named entity detection coverage
    - **Property 12: Named Entity Detection Coverage**
    - Use Hypothesis to generate text with Vietnamese name patterns; verify possible_named_individual=True and review queue reason set
    - File: `tests/property/test_pbt_export.py`
    - **Validates: Requirements 15.2**

- [ ] 17. Implement review queue, public safety, and training readiness
  - [ ] 17.1 Implement review queue builder in src/processors/review_queue.py
    - `should_review()`: return list of reasons if any conditions met (evidence C/D/E, redistribution unknown, conflict needs_review, PII error, named individual, unmasked phone/bank, extractive+not reviewed, abstractive+not reviewed)
    - `build_queue()`: aggregate all flagged records into ReviewQueue format
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [ ] 17.2 Implement public safety computation in src/processors/public_safety.py
    - Compute public_safe=True only if ALL conditions met: no raw_content/raw_article_text after sanitization, PII absent or fully redacted, redistribution satisfied, conflict resolved or empty, not pending in review queue, no prohibited/private fields
    - _Requirements: 16.2_

  - [ ] 17.3 Implement training_ready computation in src/processors/training_ready.py
    - Compute training_ready=True only if ALL 8 conditions met: public_safe=True, PII absent/redacted, redistribution satisfied, conflict resolved/empty, evidence A or B, not pending review, summary_method not abstractive unless human_reviewed, summary_method not extractive unless human_reviewed
    - _Requirements: 16.1, 16.2, 16.3_

  - [ ]* 17.4 Write property test for training readiness correctness
    - **Property 11: Training Readiness Correctness**
    - Use Hypothesis to generate records with various combinations of conditions; verify training_ready=True iff ALL 8 conditions hold simultaneously; verify training_ready=False if any single condition fails
    - File: `tests/property/test_pbt_training_ready.py`
    - **Validates: Requirements 16.2, 16.3, 8.3, 15.4**

- [ ] 18. Implement processing pipeline orchestrator
  - [ ] 18.1 Implement pipeline orchestrator in src/processors/pipeline.py
    - Orchestrate processing stages in fixed order: Clean → Label → Evidence → Dedup → Conflict → PII → NamedEntity → ReviewQueue → PublicSafety → TrainingReady
    - Read raw JSONL from data/private_raw/
    - Write processed output to data/processed_private/ (CSV/JSONL/Parquet)
    - Write review_queue.csv to data/processed_private/
    - Log processing summary: records_cleaned, duplicates_removed, pii_items_masked, labels_assigned, conflicts_detected, training_ready_count
    - _Requirements: 11.4, 12.2, 9.2_

  - [ ] 18.2 Create config/pii_patterns.yaml
    - Define regex patterns for all PII types: Vietnamese phone, bank account, CMND/CCCD, email, address, OTP, password, card number
    - _Requirements: 7.1_

- [ ] 19. Checkpoint - Milestone 3 Processing complete
  - Ensure all tests pass, ask the user if questions arise.
  - Verify: full processing pipeline runs on sample data, produces correct labels, evidence levels, deduplication, PII masking, training_ready computation

### Milestone 4: Export and Public Sanitization

- [ ] 20. Implement public sanitizer and exporters
  - [ ] 20.1 Implement public sanitizer in src/exporters/public_sanitizer.py
    - Transform data/processed_private/ → public-safe records
    - Filter: exclude conflict_status=needs_review, exclude review_queue pending records
    - Strip: remove raw_content, raw_article_text, all private-only fields
    - Apply redistribution policy: keep full URL if allowed; replace with derived features (domain_hash, url_length, path_length, query_length, tld, has_ip_address, has_punycode, has_url_shortener) if prohibited/unknown
    - Re-verify PII masking, compute public_safe, set redistribution_policy_applied, recompute training_ready
    - _Requirements: 2.6, 9.5, 9.6, 9.7, 9.11, 14.5_

  - [ ]* 20.2 Write property test for redistribution policy enforcement
    - **Property 3: Redistribution Policy Enforcement**
    - Use Hypothesis to generate records with various redistribution_status values; verify prohibited/unknown records have no full URL in public output; verify only derived features present; verify redistribution_policy_applied=True
    - File: `tests/property/test_pbt_export.py`
    - **Validates: Requirements 2.6, 9.6, 9.7**

  - [ ] 20.3 Implement processed private exporter in src/exporters/processed_private.py
    - Write CSV, JSONL, and Parquet to data/processed_private/
    - File naming: scamshield_vn_processed.{csv,jsonl,parquet}
    - Also write benign_messages_sanitized.csv
    - Log error and continue on individual file write failure
    - _Requirements: 9.2, 5.6, 9.12, 9.13_

  - [ ] 20.4 Implement public Kaggle exporter in src/exporters/public_kaggle.py
    - Write CSV, JSONL, and Parquet to data/public_kaggle/
    - File naming: scamshield_vn_public.{csv,jsonl,parquet}
    - Include benign_messages_sanitized.csv in public output
    - Log summary: files written successfully, files failed
    - Exit non-zero if any file failed
    - _Requirements: 9.3, 9.12, 9.13_

  - [ ] 20.5 Implement Excel metadata exporter in src/exporters/excel_metadata.py
    - Write .xlsx files to data/public_kaggle/: source_registry.xlsx, scam_taxonomy.xlsx, risk_signals.xlsx, data_dictionary.xlsx, review_queue_summary.xlsx, sample_records.xlsx (max 1000 rows)
    - _Requirements: 9.4_

- [ ] 21. Implement documentation and manifest generators
  - [ ] 21.1 Implement README generator in src/exporters/readme_generator.py
    - Generate README.md in data/public_kaggle/ with sections: dataset description, methodology, column definitions, label descriptions, scam type taxonomy, evidence levels, licensing, citation guidance
    - _Requirements: 9.8_

  - [ ] 21.2 Implement dataset card generator in src/exporters/dataset_card.py
    - Generate dataset_card.md conforming to Kaggle Dataset Card format: title, subtitle, description, methodology, columns, labels, limitations, ethical considerations, license
    - _Requirements: 9.9_

  - [ ] 21.3 Implement LICENSE_NOTES.md generation
    - Generate LICENSE_NOTES.md in data/public_kaggle/ with one entry per source: source_id, source_name, license_note, redistribution_status
    - _Requirements: 9.10_

  - [ ] 21.4 Implement manifest generator in src/exporters/manifest.py
    - Generate data_manifest.json in data/public_kaggle/: dataset_version, build_date, pipeline_version, total_record_count, training_ready_count, files (with file_name, row_count, file_size_bytes, sha256_checksum), source_snapshot_date, sources_used
    - Compute SHA-256 checksums for all exported files
    - Increment patch version on each new run
    - _Requirements: 17.1, 17.4, 17.5_

  - [ ] 21.5 Implement .gitignore management and PRIVATE_DATA_WARNING.md
    - Ensure .gitignore excludes data/private_raw/ and data/processed_private/
    - Log warning at startup if private directories not gitignored
    - _Requirements: 14.1, 14.6_

- [ ] 22. Checkpoint - Milestone 4 Export complete
  - Ensure all tests pass, ask the user if questions arise.
  - Verify: public sanitizer correctly strips fields, redistribution policy applied, all export formats written, documentation files generated, manifest valid

### Milestone 5: Validation and Publication Gate

- [ ] 23. Implement validators
  - [ ] 23.1 Implement PII validator in src/validators/pii_validator.py
    - Re-scan all free-text fields in data/public_kaggle/ using PII_Masker in detection-only mode
    - Report failing record_ids with PII types detected
    - Exit non-zero if any unmasked PII found
    - _Requirements: 10.2, 10.3_

  - [ ] 23.2 Implement redistribution validator in src/validators/redistribution_validator.py
    - Verify no records from prohibited/unknown sources contain full URLs or raw_content in public output
    - _Requirements: 10.4_

  - [ ] 23.3 Implement private data leakage detector in src/validators/private_leak_check.py
    - Verify no files from data/private_raw/ or data/processed_private/ copied/referenced in data/public_kaggle/
    - Verify no raw_article_text field in public output
    - Verify no contiguous text block exceeding 120 words matching copyrighted source material
    - _Requirements: 10.6, 10.7, 14.3, 14.4_

  - [ ] 23.4 Implement Kaggle publication gate in src/validators/kaggle_gate.py
    - Run 11-point checklist: (1) PII absence, (2) license compliance, (3) redistribution compliance, (4) conflict records excluded, (5) private data excluded, (6) copyright excluded, (7) extractive summaries reviewed, (8) dataset_card.md present, (9) README.md present, (10) data_manifest.json present, (11) minimum 100 training-ready records
    - Output Markdown checklist with pass/fail per check
    - Exit non-zero if any check fails, print failed items to stdout
    - _Requirements: 10.5, 10.8, 10.9, 10.10_

  - [ ] 23.5 Implement quality report generator in src/validators/quality_report.py
    - Generate Markdown report with: total records, records per label, records per evidence_level, records per source, duplicates removed, PII stats, review queue count, conflict count, training_ready vs not-ready breakdown, completeness % per required field
    - Include training_ready breakdown with reasons for non-readiness
    - Include review queue summary (total pending, breakdown by reason, oldest unreviewed)
    - _Requirements: 10.1, 15.5, 16.4_

- [ ] 24. Implement full pipeline orchestration and integration
  - [ ] 24.1 Implement `run` subcommand orchestration in src/main.py
    - Wire `run` to execute: collect → process → export → validate in sequence
    - Stop and report on fatal error at any step
    - Exit code 0 if all steps pass, non-zero otherwise
    - _Requirements: 11.7_

  - [ ]* 24.2 Write end-to-end integration test
    - Test full pipeline with small fixture data: collect (mocked sources) → process → export → validate
    - Verify: private_raw written, processed_private written, public_kaggle written, validation passes
    - File: `tests/integration/test_pipeline_e2e.py`
    - _Requirements: 11.7, 10.9_

  - [ ] 24.3 Create CHANGELOG.md in project root
    - Document initial version 1.0.0 with all implemented features
    - _Requirements: 17.2_

- [ ] 25. Final checkpoint - All milestones complete
  - Ensure all tests pass, ask the user if questions arise.
  - Verify: full `python -m src.main run` executes without errors on test data, Kaggle gate passes, quality report generated

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at each milestone boundary
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- Milestones are designed to be implemented sequentially (1 → 2 → 3 → 4 → 5)
- The processing pipeline MUST execute stages in the fixed order: Clean → Label → Evidence → Dedup → Conflict → PII → NamedEntity → ReviewQueue → PublicSafety → TrainingReady
- Deduplication runs AFTER evidence scoring because it needs evidence_level for tie-breaking
- Conflict detection runs AFTER deduplication because it uses merged source metadata
- All collectors use the shared HttpClient with retry and rate limiting
- Vietnamese source collection is seed-based (config/vietnamese_sources.yaml), NOT broad crawling

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["2.1"] },
    { "id": 3, "tasks": ["2.2", "2.3", "2.4"] },
    { "id": 4, "tasks": ["3.1", "3.2", "3.3"] },
    { "id": 5, "tasks": ["4.1", "4.2"] },
    { "id": 6, "tasks": ["4.3", "5.1", "5.2"] },
    { "id": 7, "tasks": ["7.1", "7.2"] },
    { "id": 8, "tasks": ["8.1"] },
    { "id": 9, "tasks": ["8.2", "8.3", "8.4", "9.1", "9.2", "9.3", "9.4"] },
    { "id": 10, "tasks": ["10.1", "10.2", "10.3"] },
    { "id": 11, "tasks": ["11.1"] },
    { "id": 12, "tasks": ["13.1"] },
    { "id": 13, "tasks": ["13.2", "13.3", "14.1"] },
    { "id": 14, "tasks": ["14.2", "14.3"] },
    { "id": 15, "tasks": ["14.4", "15.1"] },
    { "id": 16, "tasks": ["15.2", "15.3"] },
    { "id": 17, "tasks": ["15.4", "16.1"] },
    { "id": 18, "tasks": ["16.2", "16.3"] },
    { "id": 19, "tasks": ["16.4", "17.1"] },
    { "id": 20, "tasks": ["17.2", "17.3"] },
    { "id": 21, "tasks": ["17.4", "18.1", "18.2"] },
    { "id": 22, "tasks": ["20.1"] },
    { "id": 23, "tasks": ["20.2", "20.3"] },
    { "id": 24, "tasks": ["20.4", "20.5"] },
    { "id": 25, "tasks": ["21.1", "21.2", "21.3", "21.4", "21.5"] },
    { "id": 26, "tasks": ["23.1", "23.2", "23.3"] },
    { "id": 27, "tasks": ["23.4", "23.5"] },
    { "id": 28, "tasks": ["24.1", "24.3"] },
    { "id": 29, "tasks": ["24.2"] }
  ]
}
```
