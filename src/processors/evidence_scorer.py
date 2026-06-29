"""Evidence level scoring for ScamShield VN pipeline (Stage 3)."""

from loguru import logger

from src.models.enums import EvidenceLevel


class EvidenceScorer:
    """Scores evidence level A-E based on source metadata and credibility.
    
    Runs BEFORE deduplication so dedup can use evidence_level for tie-breaking.
    
    Rules:
      A: official/threat_feed + confirmed verification
      B: high credibility OR 2+ corroborating sources
      C: community_report with URL/screenshot/date
      D: low credibility, no corroboration
      E: no source_id or unknown credibility
    """

    def score(self, source_type: str, credibility_level: str,
              verification_status: str | None = None,
              corroborating_count: int = 1,
              has_supporting_evidence: bool = False,
              synthetic: bool = False) -> EvidenceLevel:
        """Compute evidence level for a record.
        
        Args:
            source_type: Source type enum value.
            credibility_level: Credibility level enum value.
            verification_status: Optional verification status (e.g., "verified").
            corroborating_count: Number of independent sources corroborating.
            has_supporting_evidence: Whether record has URL/screenshot/date.
            synthetic: Whether the record is synthetically generated.
            
        Returns:
            EvidenceLevel (A through E).
        """
        # Synthetic messages capped at B
        if synthetic:
            return EvidenceLevel.B

        # Level A: official or threat_feed with confirmed verification
        if source_type in ("official_government", "threat_feed"):
            if credibility_level in ("official", "high"):
                if verification_status in ("verified", "confirmed", None):
                    return EvidenceLevel.A

        # Level B: high credibility OR 2+ corroborating sources
        if credibility_level == "high" or corroborating_count >= 2:
            return EvidenceLevel.B

        # Level C: community_report with supporting evidence
        if source_type == "community_report" and has_supporting_evidence:
            return EvidenceLevel.C

        # Level D: low credibility, no corroboration
        if credibility_level == "low" or (credibility_level == "medium" and corroborating_count < 2):
            return EvidenceLevel.D

        # Level E: unknown or no source
        if credibility_level == "unknown" or not source_type:
            return EvidenceLevel.E

        # Default to C for medium credibility with some evidence
        if credibility_level == "medium":
            return EvidenceLevel.C

        return EvidenceLevel.E
