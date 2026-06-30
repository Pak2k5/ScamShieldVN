---
title: ScamShield VN
subtitle: Vietnamese Online Scam & Phishing Detection Dataset
---

# Dataset Card

## Dataset Description
ScamShield VN is a multi-source dataset combining verified phishing/malware URLs, Vietnamese scam patterns, and benign references for building scam detection models targeting the Vietnamese market.

## Motivation
Online scams targeting Vietnamese users are rapidly increasing. This dataset enables researchers to develop detection models specific to Vietnamese language and scam patterns.

## Composition
- Total records: 16673
- Training-ready records: 16673
- Record types: URL, Case, Domain, Message
- Languages: Vietnamese, English (URLs)

## Collection Process
Automated pipeline collecting from threat feeds (URLhaus, PhishTank, OpenPhish), Vietnamese government sources, and curated benign references. All collection respects robots.txt, rate limits, and source ToS.

## Preprocessing
10-stage pipeline: URL normalization, labeling, evidence scoring, deduplication, conflict detection, PII masking, named entity detection, review queue, public safety, and training readiness computation.

## Annotation Process
Labels assigned automatically from source metadata. Evidence levels scored based on source credibility. Human review required for evidence C/D/E records.

## Personal/Sensitive Information
All PII masked with type-specific tokens. No raw phone numbers, bank accounts, national IDs, emails, or addresses in public output. Private raw data never published.

## Ethical Considerations
- Dataset does not accuse individuals
- Labels describe URLs/patterns, not people
- Not for automated legal decisions
- Not for doxxing or harassment

## Limitations
- Coverage limited by source availability
- Vietnamese sources depend on robots.txt/ToS compliance
- Regex-based PII masking may miss edge cases
- Benign messages are partially synthetic

## License
Mixed licensing - see LICENSE_NOTES.md. Core dataset under CC-BY-4.0 for research use.