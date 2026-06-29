# Requirements Document

## Introduction

ScamShield VN is a Python CLI data pipeline that collects, normalizes, cleans, labels, and exports a Vietnamese online scam and phishing detection dataset. The pipeline produces two output versions: a private raw dataset for internal research and a public Kaggle-ready dataset with PII masking and redistribution compliance. The system enforces strict legal, ethical, and data provenance standards throughout collection and publication.

## Glossary

- **Pipeline**: The end-to-end Python CLI application that orchestrates data collection, processing, and export
- **Source_Registry**: A YAML configuration file defining all data sources with metadata including credibility, license, and access method
- **Collector**: A module responsible for fetching data from a single external source via its approved access method
- **Processor**: A module that transforms raw collected data through cleaning, normalization, deduplication, and labeling
- **Exporter**: A module that writes processed data to output formats and directories
- **Validator**: A module that checks data quality, PII absence, and Kaggle publication readiness
- **Private_Raw_Output**: The data/private_raw/ directory containing unmasked raw collected data only
- **Processed_Private_Output**: The data/processed_private/ directory containing cleaned, normalized, labeled private dataset with full provenance
- **Public_Kaggle_Output**: The data/public_kaggle/ directory containing PII-masked, redistribution-safe dataset for Kaggle publication
- **PII**: Personally Identifiable Information including phone numbers, bank accounts, national IDs, addresses, personal emails, OTPs, passwords, and card numbers
- **Evidence_Level**: A classification (A through E) indicating the verification strength of a data record
- **Label**: A categorical tag describing the nature of a URL or case record (e.g., phishing_url, scam_pattern, benign_url)
- **Scam_Type**: A taxonomy classification of Vietnamese online scam patterns (e.g., impersonation_government, fake_reward_gift)
- **Threat_Feed**: An external data source providing verified malicious URL or domain information (e.g., PhishTank, OpenPhish, URLhaus)
- **Benign_Reference**: A curated list of legitimate Vietnamese domains used as negative examples
- **Benign_Message**: A legitimate, non-scam message used as negative examples for text classification
- **Dataset_Card**: A structured metadata document describing the dataset contents, methodology, limitations, and usage terms for Kaggle
- **Robots_Txt_Checker**: A component that verifies whether automated access is permitted by a source before collection
- **PII_Masker**: A component that detects and replaces personally identifiable information with masked tokens or hashes
- **Review_Queue**: A list of records requiring human review before inclusion in training-ready public datasets
- **Conflict_Status**: A flag indicating that a record has contradictory labels from different sources and requires human adjudication
- **Data_Manifest**: A JSON metadata file documenting dataset version, build date, file checksums, and record counts for reproducibility
- **Redistribution_Status**: An enum field (allowed / prohibited / unknown) indicating whether a source's data may be publicly redistributed
- **Training_Ready**: A computed boolean flag indicating whether a record meets all safety, quality, and legal criteria for inclusion in ML training datasets

## Requirements

### Requirement 1: Source Registry Management

**User Story:** As a data engineer, I want to maintain a structured registry of all data sources, so that I can track provenance, access policies, and redistribution rights for every record in the dataset.

#### Acceptance Criteria

1. THE Pipeline SHALL load source definitions from a YAML configuration file located at config/sources.yaml
2. IF the config/sources.yaml file is missing or contains malformed YAML, THEN THE Pipeline SHALL raise a configuration error indicating the file path and the nature of the parsing failure, and SHALL NOT proceed with pipeline execution
3. WHEN a source entry is loaded, THE Source_Registry SHALL validate that it contains all required fields: source_id, source_name, source_url, source_type, credibility_level, license_note, access_method, and redistribution_status
4. IF a source entry is missing a required field, THEN THE Source_Registry SHALL raise a validation error identifying the missing field and the source entry's position index in the file (and source_id if available)
5. THE Source_Registry SHALL support source_type values of: official_government, threat_feed, news_media, community_report, benign_reference, and international_organization
6. THE Source_Registry SHALL support credibility_level values of: official, high, medium, low, and unknown
7. THE Source_Registry SHALL support access_method values of: public_api, public_csv, public_rss, public_webpage, manual_curated, and api_key_required
8. THE Source_Registry SHALL support redistribution_status as an enum with values: allowed, prohibited, unknown
9. IF a source entry contains a value for source_type, credibility_level, access_method, or redistribution_status that is not in the corresponding supported set, THEN THE Source_Registry SHALL raise a validation error identifying the invalid field, the invalid value, and the source_id
10. THE Source_Registry SHALL validate that source_id is unique across all entries in the registry

### Requirement 2: Legal and Ethical Access Compliance

**User Story:** As a dataset curator, I want the pipeline to enforce legal and ethical access rules, so that all data collection complies with source terms of service and applicable laws.

#### Acceptance Criteria

1. WHEN a Collector targets a web source with access_method of public_webpage or public_rss, THE Robots_Txt_Checker SHALL fetch and parse the robots.txt file for that domain before any data retrieval
2. IF robots.txt disallows access to the target path, THEN THE Collector SHALL skip that source, log a warning with the source_id and disallowed path, and record the skip reason in the collection log
3. IF the robots.txt file cannot be fetched within 10 seconds, THEN THE Collector SHALL treat the source as disallowed and log a warning indicating the timeout
4. THE Pipeline SHALL NOT collect data from sources requiring authentication bypass, captcha solving, paywall circumvention, or anti-bot evasion
5. THE Pipeline SHALL NOT collect data originating from data leaks, black markets, or illegal sources
6. WHEN a source has redistribution_status set to "prohibited" or "unknown", THE Exporter SHALL exclude raw_content and full URLs from that source in the Public_Kaggle_Output, and SHALL only include safe derived features (domain_hash, url_length, tld, threat_type, evidence_level, source_id) and aggregate statistics
7. THE Pipeline SHALL respect rate limits specified in source configuration by inserting delays between requests to the same domain, with a default of 1 request per second if no rate limit is specified
8. WHEN the Pipeline identifies a source whose terms of service explicitly prohibit automated data collection, THE Pipeline SHALL mark that source as skipped in the collection log with reason "tos_prohibits_automated_access"

### Requirement 3: Threat Feed Collection

**User Story:** As a cybersecurity researcher, I want the pipeline to collect verified phishing and malware URLs from legitimate threat feeds, so that I have a reliable foundation of labeled malicious URLs.

#### Acceptance Criteria

1. WHEN the PhishTank collector is invoked, THE Collector SHALL retrieve verified phishing URLs via the PhishTank API and store each record with source_id, url, verification_status, and submission_date
2. WHEN the OpenPhish collector is invoked, THE Collector SHALL retrieve the current phishing URL feed and store each record with source_id, url, and collection_timestamp
3. WHEN the URLhaus collector is invoked, THE Collector SHALL retrieve malware URL data via the abuse.ch API or CSV export and store each record with source_id, url, threat_type, and date_added
4. WHEN a Google Safe Browsing API key is configured, THE Collector SHALL check collected URLs against the Safe Browsing API in batches of up to 500 URLs per request, respecting the rate limits defined in the source configuration, and store the threat_match result as an enrichment field
5. WHEN a VirusTotal API key is configured, THE Collector SHALL query collected URLs for detection statistics, respecting the rate limits defined in the source configuration, and store positives_count and total_engines as enrichment fields
6. IF an API request returns an HTTP status code of 500 or above, a connection timeout exceeding 30 seconds, or a network connection error, THEN THE Collector SHALL retry up to 3 times with exponential backoff starting at 2 seconds and capped at 30 seconds before logging the failure with source_id and error details and continuing with remaining sources
7. IF a threat feed returns an HTTP 200 response with an empty record set, THEN THE Collector SHALL log an informational message with the source_id and record zero items collected without treating the response as an error
8. IF a threat feed returns an HTTP 4xx client error, THEN THE Collector SHALL skip that source without retrying, log a warning with the source_id and status code, and continue with remaining sources

### Requirement 4: Vietnamese Source Collection

**User Story:** As a dataset curator, I want to collect Vietnamese-specific scam taxonomy and case data from official and trusted sources, so that the dataset reflects the local threat landscape.

#### Acceptance Criteria

1. THE Pipeline SHALL include a curated taxonomy of Vietnamese scam types with at least 18 categories sourced from official Vietnamese cybersecurity authorities
2. WHEN collecting from Vietnamese official sources, THE Collector SHALL store case metadata including: source_id, case_summary (paraphrased, maximum 120 words for public output), scam_type, date_reported, and source_url
3. THE Collector SHALL NOT store full copyrighted article text from news sources in any output; only metadata and a paraphrased summary are permitted
4. WHEN collecting domain data from Tín Nhiệm Mạng, THE Collector SHALL store each record with source_id, domain, status (one of: scam, phishing, malware, suspicious, or unverified), and date_checked
5. THE Pipeline SHALL include Vietnamese scam type taxonomy covering: impersonation_government, impersonation_bank, impersonation_logistics, impersonation_ecommerce, fake_reward_gift, fake_job_task, investment_crypto_forex, romance_scam, fake_receipt, sim_lock_standardization, social_account_takeover, recovery_scam, fake_app_remote_access, qr_phishing, malware_distribution, gambling_lottery_scam, counterfeit_goods, and other
6. WHEN a case record's scam_type value is not present in the taxonomy defined in config/taxonomy_seed.yaml, THEN THE Collector SHALL assign scam_type "other" and log a warning with the unrecognized value and source_id
7. IF a Vietnamese source collector encounters a network or parsing error, THEN THE Collector SHALL log the error with source_id and error details, skip the failed source, and continue processing remaining Vietnamese sources
8. EACH public case summary SHALL include fields: summary_method (one of: manual, extractive, abstractive, rule_based) and human_reviewed (boolean, default false)
9. IF summary_method="extractive" AND human_reviewed=false, THEN THE record SHALL be added to the Review_Queue and SHALL NOT be included in training-ready public files

### Requirement 5: Benign Reference Data

**User Story:** As a machine learning researcher, I want the dataset to include verified benign domains and benign messages, so that models can learn to distinguish legitimate from malicious content.

#### Acceptance Criteria

1. THE Pipeline SHALL include a curated list of legitimate Vietnamese domains from categories: banking, e-wallet, e-commerce, logistics, telecommunications, and government, with a minimum of 5 domains per category
2. THE Pipeline SHALL collect the top 1000 ranked domains from the Tranco List as international benign references
3. WHEN a benign domain is added, THE Pipeline SHALL store: source_id, domain, category, organization_name, and verification_method, where verification_method is one of: manual_curated, tranco_ranking, or official_registry
4. THE Pipeline SHALL label all benign reference records with label value benign_url and evidence_level A
5. IF the Tranco List is unavailable during collection, THEN THE Pipeline SHALL retry up to 3 times with exponential backoff before logging the failure and continuing with remaining sources
6. THE Pipeline SHALL produce a benign_messages_sanitized.csv containing legitimate Vietnamese messages including: OTP warning messages from banks, delivery notifications, bank educational messages, and ordinary non-scam promotional messages
7. EACH benign message record SHALL include fields: message_id, text_sanitized, benign_message_type (one of: otp_warning, delivery_notification, bank_education, promotion, system_notification, other), synthetic (boolean), source_type (one of: official_source, derived, manually_curated), human_reviewed (boolean), source_ids, evidence_level, and collected_at
8. IF a benign message is synthetically generated, THE Pipeline SHALL set synthetic=true and SHALL NOT assign evidence_level higher than B

### Requirement 6: Data Cleaning and Normalization

**User Story:** As a data engineer, I want collected data to be cleaned and normalized to consistent formats, so that downstream analysis and model training can proceed without data quality issues.

#### Acceptance Criteria

1. WHEN a URL is processed, THE Processor SHALL normalize the URL by lowercasing the scheme and domain, removing trailing slashes, removing default port numbers (80 for http, 443 for https), and sorting query parameters alphabetically
2. IF a URL cannot be parsed due to malformed syntax, THEN THE Processor SHALL log a warning with the record_id and raw URL value, mark the record with a normalization_error flag, and retain the original URL value without modification
3. WHEN text content is processed, THE Processor SHALL normalize Unicode to NFC form, strip Unicode control characters in categories Cc and Cf (excluding newline, tab, and carriage return), and collapse multiple whitespace characters into single spaces while preserving Vietnamese diacritical marks
4. WHEN duplicate records are detected based on normalized URL hash, THE Processor SHALL retain the record with the highest evidence_level; if evidence_level is tied, retain the record with the earliest first_seen timestamp, and merge all source_ids into the retained record's source_ids list
5. THE Processor SHALL assign a unique record_id (UUID v4) to each deduplicated record in the output dataset

### Requirement 7: PII Detection and Masking

**User Story:** As a dataset curator, I want all personally identifiable information to be detected and masked before public release, so that no individual's private data is exposed.

#### Acceptance Criteria

1. THE PII_Masker SHALL scan all free-text fields (case_summary, raw_content, text_sanitized, and any user-supplied string fields) in each record to detect the following PII types: Vietnamese phone numbers (10-digit numbers starting with 0 or prefixed with +84), bank account numbers (sequences of 6 to 19 digits matching Vietnamese bank formats), national ID numbers (9-digit CMND or 12-digit CCCD), personal email addresses (per RFC 5322 local-part@domain format), physical addresses (strings containing Vietnamese province/city names combined with district/ward identifiers or street numbers), OTP codes (isolated numeric sequences of 4 to 8 digits in OTP-related context), passwords (values adjacent to password-related keywords), and payment card numbers (13 to 19 digit sequences passing Luhn validation)
2. WHEN PII is detected in a record destined for Public_Kaggle_Output, THE PII_Masker SHALL replace each PII instance with a type-specific masked token: [PHONE_REDACTED], [BANK_ACCOUNT_REDACTED], [EMAIL_REDACTED], [ID_REDACTED], [ADDRESS_REDACTED], [OTP_REDACTED], [PASSWORD_REDACTED], [CARD_REDACTED]
3. THE PII_Masker SHALL preserve the Private_Raw_Output with original unmasked data for internal research use only
4. WHEN a record contains PII, THE PII_Masker SHALL set a pii_detected flag to true and record the count of masked items per PII type in a pii_summary field
5. IF the PII_Masker encounters an error while processing a record, THEN THE PII_Masker SHALL exclude that record from Public_Kaggle_Output, add it to the Review_Queue with reason "pii_masking_error", log a warning with the record_id and error details, and continue processing remaining records

### Requirement 8: Labeling and Classification

**User Story:** As a researcher, I want each record to carry structured labels indicating threat type, scam category, and risk signals, so that the dataset supports multi-label classification tasks.

#### Acceptance Criteria

1. THE Processor SHALL assign exactly one primary label to each record from the set: phishing_url, malware_url, scam_case, scam_pattern, suspicious, community_reported_unverified, benign_url, benign_message, unknown
2. IF a record appears in both a benign source AND a malicious/threat source, THEN THE Processor SHALL NOT automatically resolve the conflict; instead it SHALL assign conflict_status="needs_review", set conflict_reason describing the contradicting sources, exclude the record from training-ready public files, and add it to the Review_Queue
3. WHEN conflict_status="needs_review", THE record SHALL include fields: reviewed_by (string, default empty), reviewed_at (datetime, default null), and SHALL NOT appear in public_kaggle training-ready files until conflict_status is changed to "resolved"
4. WHEN a record originates from a source with credibility_level "official" or source_type "threat_feed" and has verification_status marked as confirmed, THE Processor SHALL assign evidence_level A
5. WHEN a record originates from a source with credibility_level "high" or is corroborated by at least 2 independent sources, THE Processor SHALL assign evidence_level B
6. WHEN a record originates from a source with source_type "community_report" and includes at least one of: a URL, a screenshot reference, or a date_reported field, THE Processor SHALL assign evidence_level C
7. WHEN a record originates from a source with credibility_level "low" or has no corroborating source, THE Processor SHALL assign evidence_level D
8. WHEN a record has no source_id or the source has credibility_level "unknown", THE Processor SHALL assign evidence_level E
9. THE Processor SHALL assign zero or more scam_type values from the Vietnamese scam taxonomy as a multi-label field, with a maximum of 5 scam_type values per record
10. THE Pipeline SHALL NOT label any record with language implying a named individual is a scammer; labels SHALL reference only URLs, patterns, and cases, and the Processor SHALL strip personal names from all label-related fields before assignment
11. IF the Processor cannot determine a primary label due to insufficient metadata, THEN THE Processor SHALL assign the label "unknown" and evidence_level E

### Requirement 9: Data Export

**User Story:** As a data engineer, I want the pipeline to export data in multiple formats to appropriate directories, so that the dataset serves different consumption needs while maintaining clear separation between raw, processed, and public data.

#### Acceptance Criteria

1. THE Exporter SHALL write raw collected data to data/private_raw/ in JSONL format only, preserving original unprocessed records as received from sources
2. THE Exporter SHALL write the cleaned, normalized, labeled full dataset to data/processed_private/ in CSV, JSONL, and Parquet formats, with each file named using the pattern `scamshield_vn_processed.<ext>`
3. THE Exporter SHALL write the PII-masked, redistribution-compliant dataset to data/public_kaggle/ in CSV, JSONL, and Parquet formats, with each file named using the pattern `scamshield_vn_public.<ext>`
4. THE Exporter SHALL write Excel (.xlsx) files ONLY for smaller metadata and reference files: source_registry, scam_taxonomy, risk_signals, data_dictionary, review_queue_summary, and a sample of up to 1000 records from the main dataset
5. WHEN exporting to public_kaggle/, THE Exporter SHALL exclude raw_content and raw_article_text fields; public output SHALL only include: summary_vi, source_url, published_date, scam_type, risk_signals, label, evidence_level, and derived metadata
6. WHEN exporting URL records to public_kaggle/, THE Exporter SHALL apply redistribution policy: IF redistribution_status="allowed" THEN include full URL; IF redistribution_status="prohibited" or "unknown" THEN exclude full URL and only include domain_hash, url_length, path_length, query_length, tld, has_ip_address, has_punycode, has_url_shortener, threat_type, evidence_level, and source_id
7. EACH exported URL record in public_kaggle/ SHALL include a field redistribution_policy_applied (boolean) indicating whether URL redaction was applied due to source redistribution restrictions
8. THE Exporter SHALL generate a README.md file in public_kaggle/ containing sections: dataset description, methodology summary, column definitions, label descriptions, scam type taxonomy, evidence level definitions, licensing information, and citation guidance
9. THE Exporter SHALL generate a dataset_card.md file conforming to Kaggle Dataset Card format with sections: title, subtitle, description, methodology, columns, labels, limitations, ethical considerations, and license
10. THE Exporter SHALL include a LICENSE_NOTES.md file in public_kaggle/ containing one entry per source, with: source_id, source_name, license_note, and redistribution_status
11. THE Exporter SHALL exclude all records with conflict_status="needs_review" from public_kaggle/ training-ready output files
12. IF a file write operation fails during export, THEN THE Exporter SHALL log an error identifying the target file path and failure reason, skip the failed file, and continue exporting remaining formats
13. WHEN export of all formats completes, THE Exporter SHALL log a summary indicating the count of files successfully written and the count of files that failed, and exit with a non-zero status code if any file failed

### Requirement 10: Data Quality and Validation

**User Story:** As a dataset curator, I want automated quality checks and a Kaggle safety validator, so that I can verify dataset integrity and publication readiness before release.

#### Acceptance Criteria

1. THE Validator SHALL generate a data quality report in Markdown format containing: total record count, records per label, records per evidence_level, records per source, duplicate count removed during processing, PII detection statistics (total items detected and masked per PII type), records in review queue, records with conflict_status, training_ready count vs not-ready count, and completeness percentage for each required field
2. THE Validator SHALL verify that zero records in Public_Kaggle_Output contain unmasked PII by running the PII_Masker in detection-only mode on all free-text fields
3. IF unmasked PII is found in Public_Kaggle_Output, THEN THE Validator SHALL report the failing record_ids with the PII types detected, write a PII violation report, and exit with a non-zero status code to block publication
4. THE Validator SHALL verify that no records from sources with redistribution_status="prohibited" or "unknown" contain full URLs or raw_content in Public_Kaggle_Output
5. THE Validator SHALL verify that no records with conflict_status="needs_review" appear in Public_Kaggle_Output training-ready files
6. THE Validator SHALL verify that no files from data/private_raw/ or data/processed_private/ have been copied or referenced in data/public_kaggle/
7. THE Validator SHALL verify that Public_Kaggle_Output contains no raw_article_text field and no contiguous text block exceeding 120 words that matches copyrighted source material
8. THE Validator SHALL verify that records with summary_method="extractive" and human_reviewed=false are NOT present in public_kaggle/ training-ready files
9. THE Validator SHALL produce a Kaggle publish checklist in Markdown format confirming: PII absence (pass/fail), license compliance (pass/fail), redistribution policy compliance (pass/fail), conflict records excluded (pass/fail), private data excluded (pass/fail), copyrighted content excluded (pass/fail), extractive summaries reviewed (pass/fail), dataset card presence (pass/fail), README presence (pass/fail), data manifest presence (pass/fail), and minimum record count of 100 training-ready records met (pass/fail)
10. IF any checklist item fails, THEN THE Validator SHALL exit with a non-zero status code and print the failed items to stdout

### Requirement 11: CLI Interface

**User Story:** As a developer, I want to operate the entire pipeline through a command-line interface, so that I can automate runs and integrate with CI/CD workflows.

#### Acceptance Criteria

1. THE Pipeline SHALL provide a CLI entry point invokable as `python -m src.main` with subcommand routing
2. THE Pipeline SHALL support the following subcommands: collect, process, export, validate, and run (full pipeline)
3. WHEN the `collect` subcommand is invoked with a `--source` flag, THE Pipeline SHALL execute only the data collection phase for the specified source_id; WHEN invoked without `--source`, THE Pipeline SHALL collect from all sources in the registry
4. WHEN the `process` subcommand is invoked, THE Pipeline SHALL execute cleaning, deduplication, labeling, evidence scoring, and training_ready computation on collected data in data/private_raw/, writing results to data/processed_private/
5. WHEN the `export` subcommand is invoked with a `--target` flag value of "kaggle", THE Pipeline SHALL generate output files to data/public_kaggle/ only; WHEN invoked without `--target`, THE Pipeline SHALL export to both data/processed_private/ and data/public_kaggle/
6. WHEN the `validate` subcommand is invoked, THE Pipeline SHALL run quality checks and the Kaggle safety validator and print results to stdout in a human-readable format
7. WHEN the `run` subcommand is invoked, THE Pipeline SHALL execute collect, process, export, and validate in sequence; IF any step fails with a fatal error, THEN the pipeline SHALL stop execution and report the failed step
8. THE Pipeline SHALL accept a `--config` flag to specify a custom path to the source registry YAML file
9. THE Pipeline SHALL accept a `--output-dir` flag to specify a custom base output directory
10. IF a subcommand is invoked with an unrecognized flag or missing required argument, THEN THE Pipeline SHALL print a usage message describing available flags and exit with status code 2
11. IF a subcommand encounters a fatal error, THEN THE Pipeline SHALL log the error with context including the subcommand name and timestamp, and exit with a non-zero status code
12. THE Pipeline SHALL accept a `--verbose` flag that sets log level to DEBUG for detailed output

### Requirement 12: Logging and Observability

**User Story:** As a data engineer, I want structured logging throughout the pipeline, so that I can monitor execution, diagnose failures, and audit data collection activities.

#### Acceptance Criteria

1. THE Pipeline SHALL log all collection activities in JSON format including fields: timestamp, level, source_id, event_type, records_fetched, duration_seconds, and error_message (if applicable)
2. THE Pipeline SHALL log processing statistics including: records_cleaned, duplicates_removed, pii_items_masked, labels_assigned, conflicts_detected, and training_ready_count as a single JSON summary event at the end of the process phase
3. THE Pipeline SHALL write logs to both stdout (for interactive use) and a timestamped log file named `pipeline_YYYYMMDD_HHMMSS.log` in the reports/ directory
4. WHEN a Collector skips a source due to policy violation, THE Pipeline SHALL log a warning at level WARN with fields: source_id, skip_reason, and target_path
5. THE Pipeline SHALL support a `--verbose` CLI flag that sets log level to DEBUG; without this flag, the default log level SHALL be INFO

### Requirement 13: Configuration and Environment

**User Story:** As a developer, I want API keys and sensitive configuration managed through environment variables, so that credentials are not committed to version control.

#### Acceptance Criteria

1. THE Pipeline SHALL load API keys from environment variables named SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY, SCAMSHIELD_VIRUSTOTAL_KEY, and SCAMSHIELD_PHISHTANK_KEY, and SHALL also read from a .env file located in the project root directory, with environment variables taking precedence over .env file values
2. WHEN an optional API key (Google Safe Browsing or VirusTotal) is not configured, THE Pipeline SHALL skip the corresponding enrichment step and log a message at INFO level identifying the skipped service by name
3. IF a configured API key is present but contains an empty string or only whitespace, THEN THE Pipeline SHALL treat it as not configured, log a warning identifying the affected service, and continue with remaining sources
4. THE Pipeline SHALL load pipeline configuration (output paths, rate limits, retry settings) from a config/pipeline.yaml file with the following defaults when a setting is absent: output directory ./data, rate limit of 1 request per second per domain, maximum 3 retry attempts with exponential backoff starting at 1 second
5. IF the config/pipeline.yaml file does not exist, THEN THE Pipeline SHALL use all default values and log an informational message indicating that default configuration is in use

### Requirement 14: Private Data Protection

**User Story:** As a data engineer, I want private raw data to be protected from accidental publication, so that sensitive unmasked data never reaches public repositories or Kaggle uploads.

#### Acceptance Criteria

1. THE Pipeline SHALL create a .gitignore file (or append to existing) that excludes data/private_raw/ and data/processed_private/ from version control
2. THE Pipeline SHALL generate a PRIVATE_DATA_WARNING.md file in data/private_raw/ with clear warnings that the directory contains unmasked PII and must never be committed, uploaded, or shared publicly
3. THE Validator SHALL verify that no files from data/private_raw/ or data/processed_private/ are present in or referenced by data/public_kaggle/
4. IF the Validator detects private data leakage into public_kaggle/, THEN THE Validator SHALL fail with a critical error listing the affected files and exit with a non-zero status code
5. THE public export pipeline SHALL NOT read from or depend on raw PII values in data/private_raw/; all public output SHALL be derived from already-masked intermediate data in data/processed_private/
6. THE Pipeline SHALL include data/private_raw/ and data/processed_private/ in .gitignore by default and SHALL log a warning at startup if these directories are not gitignored

### Requirement 15: Manual Review Queue

**User Story:** As a dataset curator, I want a structured review queue for records that cannot be automatically validated, so that human reviewers can inspect and approve edge cases before public release.

#### Acceptance Criteria

1. THE Pipeline SHALL generate a review_queue.csv file in data/processed_private/ containing all records that require human review
2. A record SHALL be added to the Review_Queue if any of the following conditions are met: evidence_level is C, D, or E; source has redistribution_status="unknown"; conflict_status="needs_review"; PII masking encountered an error; record contains named individuals; record contains unmasked phone numbers or bank account numbers; summary_method="extractive" and human_reviewed=false
3. EACH Review_Queue record SHALL include fields: record_id, review_reason (list), source_ids, label, evidence_level, conflict_status, pii_detected, requires_action (one of: approve, reject, edit, escalate), reviewer_assigned, reviewed_by, reviewed_at, review_notes
4. THE Pipeline SHALL NOT include records from the Review_Queue in public_kaggle/ training-ready files unless reviewed_by is not empty and requires_action="approve"
5. THE Pipeline SHALL generate a review queue summary in the data quality report showing: total records pending review, breakdown by review_reason, and age of oldest unreviewed record

### Requirement 16: Training Readiness Assessment

**User Story:** As a machine learning researcher, I want each public record to clearly indicate whether it is safe and reliable enough for model training, so that I can filter the dataset appropriately without manual inspection.

#### Acceptance Criteria

1. EACH record in public_kaggle/ SHALL include a training_ready field (boolean)
2. THE Pipeline SHALL set training_ready=true ONLY IF all of the following conditions are satisfied: public_safe=true; pii_detected=false OR pii_redacted=true; redistribution policy is satisfied (redistribution_status="allowed" OR redistribution_policy_applied=true with only derived features); conflict_status is empty or "resolved"; evidence_level is A or B; record is NOT pending in Review_Queue (not present in review_queue.csv with requires_action != "approve")
3. IF any of the conditions in AC2 are not met, THE Pipeline SHALL set training_ready=false
4. THE data quality report SHALL include a breakdown of training_ready=true vs training_ready=false counts with reasons for non-readiness
5. THE Exporter SHALL include training_ready as a filterable column in all public_kaggle/ output formats (CSV, JSONL, Parquet) so consumers can easily select training-safe records

### Requirement 17: Dataset Versioning and Manifest

**User Story:** As a data publisher, I want each dataset release to have clear versioning and a manifest, so that consumers can track changes, verify integrity, and reproduce results.

#### Acceptance Criteria

1. THE Pipeline SHALL generate a data_manifest.json file in data/public_kaggle/ containing: dataset_version (semantic version string), build_date (ISO 8601), pipeline_version, total_record_count, training_ready_count, files (array of objects with file_name, row_count, file_size_bytes, sha256_checksum), source_snapshot_date, and sources_used (list of source_ids)
2. THE Pipeline SHALL generate a CHANGELOG.md file in the project root documenting changes between dataset versions, with entries containing: version, date, summary of changes (sources added/removed, record count changes, schema changes, bug fixes)
3. THE Pipeline SHALL include a dataset_version field in the dataset_summary.json output, matching the version in data_manifest.json
4. WHEN a new pipeline run produces output, THE Pipeline SHALL increment the patch version in data_manifest.json; major and minor version changes SHALL be manual
5. THE Pipeline SHALL compute SHA-256 checksums for all exported files and include them in data_manifest.json for integrity verification
