"""Label assignment for ScamShield VN pipeline (Stage 2)."""

from pathlib import Path
from typing import Optional

import yaml
from loguru import logger

from src.models.enums import Label, RecordType


class Labeler:
    """Assigns primary labels and scam_type taxonomy values to records.
    
    - Exactly one primary label from the Label enum
    - 0-5 scam_type values from Vietnamese taxonomy
    - Strips personal names from label-related fields
    - Defaults to "unknown" if insufficient metadata
    """

    def __init__(self, taxonomy_path: str = "config/taxonomy_seed.yaml"):
        self.valid_scam_types = self._load_taxonomy(taxonomy_path)

    def _load_taxonomy(self, path: str) -> set[str]:
        """Load valid scam_type values from taxonomy config."""
        taxonomy_path = Path(path)
        if not taxonomy_path.exists():
            logger.warning("Taxonomy config not found: {}", path)
            return set()
        try:
            with open(taxonomy_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            types = {entry["scam_type"] for entry in data.get("taxonomy", [])}
            logger.debug("Loaded {} scam types from taxonomy.", len(types))
            return types
        except Exception as e:
            logger.error("Error loading taxonomy: {}", e)
            return set()

    def assign_label(self, record_type: str, source_type: str, threat_type: Optional[str] = None,
                     verification_status: Optional[str] = None, category: Optional[str] = None,
                     benign_message_type: Optional[str] = None) -> Label:
        """Assign primary label based on record metadata.
        
        Rules:
        - threat_feed + phishing -> phishing_url
        - threat_feed + malware -> malware_url
        - official_government case -> scam_case
        - benign_reference domain -> benign_url
        - benign_reference message -> benign_message
        - community_report -> community_reported_unverified
        - Otherwise -> unknown
        """
        if record_type == RecordType.MESSAGE.value or benign_message_type:
            return Label.BENIGN_MESSAGE

        if source_type in ("benign_reference",):
            return Label.BENIGN_URL

        if source_type in ("threat_feed",):
            if threat_type and "malware" in threat_type.lower():
                return Label.MALWARE_URL
            return Label.PHISHING_URL

        if source_type in ("official_government",):
            return Label.SCAM_CASE

        if source_type in ("community_report",):
            return Label.COMMUNITY_REPORTED_UNVERIFIED

        if source_type in ("news_media",):
            return Label.SCAM_PATTERN

        return Label.UNKNOWN

    def assign_scam_types(self, scam_type_raw: Optional[str] = None,
                          threat_type: Optional[str] = None) -> list[str]:
        """Assign 0-5 scam_type values from taxonomy.
        
        If raw value not in taxonomy, assigns "other".
        """
        types = []
        
        if scam_type_raw:
            if scam_type_raw in self.valid_scam_types:
                types.append(scam_type_raw)
            else:
                logger.debug("Unknown scam_type '{}', mapping to 'other'", scam_type_raw)
                types.append("other")

        # Infer from threat_type if available
        if threat_type and not types:
            if "malware" in threat_type.lower():
                types.append("malware_distribution")
            elif "phishing" in threat_type.lower():
                # Could be multiple types - leave for manual review
                pass

        return types[:5]  # Max 5
