"""PII detection and masking for ScamShield VN pipeline (Stage 6)."""

import re
from pathlib import Path
from typing import Optional

import yaml
from loguru import logger


class PIIMasker:
    """Detects and masks Personally Identifiable Information in text fields.
    
    Scans free-text fields and replaces PII with type-specific tokens.
    Sets pii_detected flag and populates pii_summary counts.
    """

    DEFAULT_PATTERNS = {
        "phone": {
            "regex": r"(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])\d{7}",
            "token": "[PHONE_REDACTED]",
        },
        "email": {
            "regex": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "token": "[EMAIL_REDACTED]",
        },
        "national_id_cccd": {
            "regex": r"(?:CCCD|căn cước|c[aă]n\s*c[uư][ơớ]c)\s*[:\-]?\s*(\d{12})",
            "token": "[ID_REDACTED]",
        },
        "national_id_cmnd": {
            "regex": r"(?:CMND|ch[uứ]ng\s*minh)\s*[:\-]?\s*(\d{9})",
            "token": "[ID_REDACTED]",
        },
        "bank_account": {
            "regex": r"(?:(?:s[ốo]\s*(?:t[àa]i\s*kho[aả]n|TK)|STK|tài khoản)\s*[:\-]?\s*)(\d{6,19})",
            "token": "[BANK_ACCOUNT_REDACTED]",
        },
        "otp": {
            "regex": r"(?:OTP|m[aã]\s*(?:x[aá]c\s*th[uự]c|bảo mật|xác nhận))\s*[:\-]?\s*(\d{4,8})",
            "token": "[OTP_REDACTED]",
        },
        "card_number": {
            "regex": r"\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7})\b",
            "token": "[CARD_REDACTED]",
        },
    }

    def __init__(self, patterns_path: str = "config/pii_patterns.yaml"):
        self.patterns = self._load_patterns(patterns_path)

    def _load_patterns(self, path: str) -> dict[str, dict]:
        """Load PII patterns from YAML config, falling back to defaults."""
        config_path = Path(path)
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if data and "patterns" in data:
                    return data["patterns"]
            except Exception as e:
                logger.warning("Error loading PII patterns from {}: {}", path, e)
        return self.DEFAULT_PATTERNS

    def mask_text(self, text: str) -> tuple[str, dict[str, int]]:
        """Mask PII in text, returning masked text and summary counts.
        
        Args:
            text: Input text to scan for PII.
            
        Returns:
            Tuple of (masked_text, pii_summary_counts).
        """
        if not text:
            return text, {}

        pii_counts: dict[str, int] = {}
        masked = text

        for pii_type, config in self.patterns.items():
            regex = config.get("regex", "")
            token = config.get("token", f"[{pii_type.upper()}_REDACTED]")
            
            if not regex:
                continue
                
            try:
                pattern = re.compile(regex, re.IGNORECASE)
                matches = pattern.findall(masked)
                if matches:
                    pii_counts[pii_type] = len(matches)
                    masked = pattern.sub(token, masked)
            except re.error as e:
                logger.warning("Invalid PII regex for '{}': {}", pii_type, e)

        return masked, pii_counts

    def mask_record(self, record: dict) -> dict:
        """Mask PII in all text fields of a record.
        
        Scans: case_summary, text_sanitized, raw_content, raw_article_text.
        Sets pii_detected and pii_summary.
        """
        text_fields = ["case_summary", "text_sanitized", "raw_content", "raw_article_text"]
        total_pii: dict[str, int] = {}

        for field in text_fields:
            value = record.get(field)
            if value and isinstance(value, str):
                masked_value, counts = self.mask_text(value)
                record[field] = masked_value
                for pii_type, count in counts.items():
                    total_pii[pii_type] = total_pii.get(pii_type, 0) + count

        if total_pii:
            record["pii_detected"] = True
            record["pii_redacted"] = True
            record["pii_summary"] = total_pii
        else:
            record["pii_detected"] = False

        return record

    def detect_only(self, text: str) -> dict[str, int]:
        """Detect PII without masking (for validation pass)."""
        if not text:
            return {}
        counts: dict[str, int] = {}
        for pii_type, config in self.patterns.items():
            regex = config.get("regex", "")
            if not regex:
                continue
            try:
                matches = re.findall(regex, text, re.IGNORECASE)
                if matches:
                    counts[pii_type] = len(matches)
            except re.error:
                pass
        return counts
