# ScamShield VN – Vietnamese Online Scam & Phishing Detection Dataset

## Description
A curated dataset for research and development of Vietnamese online scam and phishing detection models. Contains verified phishing/malware URLs, Vietnamese scam case patterns, benign reference domains, and benign messages.

## Methodology
Data collected from verified threat feeds (URLhaus CC0, PhishTank, OpenPhish), Vietnamese official cybersecurity authorities, and curated benign references. All records processed through a 10-stage pipeline: Clean → Label → Evidence → Dedup → Conflict → PII Mask → Named Entity → Review Queue → Public Safety → Training Ready.

## Column Definitions
- `record_id`: Unique UUID v4 identifier
- `label`: Primary classification (phishing_url, malware_url, scam_case, benign_url, benign_message, unknown)
- `evidence_level`: Verification strength (A=strongest, E=weakest)
- `training_ready`: Boolean - safe and reliable enough for ML training
- `redistribution_policy_applied`: Whether URL was redacted due to source restrictions

## Label Schema
- `phishing_url`: Verified phishing URL from threat feed
- `malware_url`: Verified malware distribution URL
- `scam_case`: Vietnamese scam case from official sources
- `benign_url`: Verified legitimate domain
- `benign_message`: Legitimate non-scam message
- `unknown`: Insufficient evidence for classification

## Evidence Levels
- A: Official government/verified threat feed confirmation
- B: High credibility source or 2+ corroborating sources
- C: Community report with supporting evidence
- D: Low credibility, unverified
- E: Unknown/insufficient evidence

## Scam Type Taxonomy (Vietnamese)
18 categories including: impersonation_government, impersonation_bank, fake_reward_gift, investment_crypto_forex, romance_scam, qr_phishing, malware_distribution, and more.

## PII Redaction Policy
All personally identifiable information is masked before public release. Tokens: [PHONE_REDACTED], [EMAIL_REDACTED], [ID_REDACTED], [BANK_ACCOUNT_REDACTED], etc.

## Licensing
See LICENSE_NOTES.md for per-source licensing details. Some sources allow full redistribution (CC0); others are restricted to derived features only.

## Known Limitations
- Vietnamese sources may have limited coverage depending on robots.txt/ToS
- Evidence level D/E records are not training-ready
- Dataset does not make legal conclusions about individuals
- PII masking is regex-based and may have false negatives

## Ethical Use Warning
This dataset is for RESEARCH PURPOSES ONLY. Do NOT use to:
1. Accuse individuals of crimes
2. Doxx or harass anyone
3. Make automated legal decisions
4. Redistribute raw PII

## Citation
```
@dataset{scamshield_vn_2024,
  title={ScamShield VN: Vietnamese Online Scam & Phishing Detection Dataset},
  author={ScamShield VN Team},
  year={2024},
  url={https://github.com/Pak2k5/ScamShieldVN}
}
```