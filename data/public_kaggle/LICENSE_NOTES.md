# License Notes

This document describes the licensing and redistribution terms for each data source used in the ScamShield VN dataset.

## Summary

| Source ID | Source Name | Redistribution | License Note |
|-----------|-------------|----------------|--------------|
| phishtank_verified | PhishTank Verified Phishing | allowed | Free for non-commercial research use; attribution required |
| openphish_feed | OpenPhish Community Feed | unknown | Community feed publicly available; commercial use terms unclear |
| urlhaus_malware | URLhaus Malware URL Exchange | allowed | CC0 1.0 Universal - Public Domain Dedication |
| google_safe_browsing | Google Safe Browsing | prohibited | Google API Terms of Service; data may not be redistributed |
| virustotal | VirusTotal | prohibited | VirusTotal API Terms; redistribution of raw results prohibited |
| vietnamese_official | Vietnamese Official Cybersecurity Sources | unknown | Government public information; redistribution terms not explicitly stated |
| tin_nhiem_mang | Tín Nhiệm Mạng - Trung tâm Giám sát an toàn không gian mạng quốc gia | unknown | Government public service; redistribution terms not explicitly stated |
| tranco_top1000 | Tranco Top 1 Million - Top 1000 Subset | allowed | Publicly available ranking list; free to use for research |
| benign_domains_vn | Curated Vietnamese Benign Domains | allowed | Manually curated list of verified legitimate Vietnamese domains |
| benign_messages | Curated Benign Vietnamese Messages | allowed | Manually curated and synthetic benign messages for negative examples |

## Redistribution Policy

- **allowed**: Full data may be included in public output.
- **prohibited**: Only derived features (domain hash, URL length, TLD) are public. Raw URLs/content excluded.
- **unknown**: Treated as prohibited for safety. Only derived features exported publicly.

## Dataset License

The curated portions of this dataset (taxonomy, benign domains, benign messages) are released under CC-BY-4.0.
Third-party data retains its original license. See individual source entries above.

## Important Notes

- Private raw data (data/private_raw/) is NEVER published
- PII is masked in all public output
- This dataset does not make legal conclusions about individuals or organizations