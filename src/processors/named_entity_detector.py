"""Vietnamese named entity detection for ScamShield VN pipeline (Stage 7).

Lightweight heuristic-based detection of personal names in Vietnamese text.
Flags records for review queue - does NOT make final decisions.
"""

import re

from loguru import logger


class NamedEntityDetector:
    """Detects possible personal names in Vietnamese text using heuristics.
    
    Patterns detected:
    - anh/chị/ông/bà + Capitalized Name
    - "đứng tên [Name]"
    - "[Name] lừa đảo" / "[Name] chiếm đoạt"
    - Vietnamese name patterns (2-4 capitalized syllables)
    
    False positives are acceptable (sent to review queue).
    False negatives (missed names in public output) are the higher risk.
    """

    # Vietnamese honorific prefixes followed by capitalized names
    HONORIFIC_PATTERN = re.compile(
        r"(?:anh|chị|ông|bà|cô|chú|bác|em|cháu|thầy|cô)\s+"
        r"([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+){1,3})",
        re.UNICODE
    )

    # "đứng tên [Name]" pattern
    OWNERSHIP_PATTERN = re.compile(
        r"đứng\s+tên\s+([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+){1,3})",
        re.UNICODE
    )

    # "[Name] lừa đảo/chiếm đoạt/lừa" accusation pattern  
    ACCUSATION_PATTERN = re.compile(
        r"([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+){1,3})\s+"
        r"(?:lừa đảo|chiếm đoạt|lừa|bị tố|đã lừa)",
        re.UNICODE
    )

    # Standalone Vietnamese full name (2-4 capitalized syllables, not at line start to avoid titles)
    NAME_PATTERN = re.compile(
        r"(?<=[,.\s])([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+){2,3})(?=[,.\s]|$)",
        re.UNICODE
    )

    def detect_names(self, text: str) -> list[str]:
        """Detect possible personal name spans in text.
        
        Args:
            text: Vietnamese text to scan.
            
        Returns:
            List of possible name strings found.
        """
        if not text:
            return []

        names = set()

        for pattern in [self.HONORIFIC_PATTERN, self.OWNERSHIP_PATTERN, 
                       self.ACCUSATION_PATTERN, self.NAME_PATTERN]:
            matches = pattern.findall(text)
            for match in matches:
                name = match.strip()
                if len(name) > 3 and not self._is_likely_organization(name):
                    names.add(name)

        return list(names)

    def _is_likely_organization(self, name: str) -> bool:
        """Filter out likely organization names (not personal)."""
        org_keywords = {
            "Ngân hàng", "Công ty", "Tập đoàn", "Bộ", "Sở", "Cục",
            "Vietcombank", "BIDV", "Techcombank", "Shopee", "Lazada",
            "Vietnam", "Việt Nam", "Công an", "Viện"
        }
        for keyword in org_keywords:
            if keyword.lower() in name.lower():
                return True
        return False

    def flag_record(self, record: dict) -> dict:
        """Flag record if possible personal names detected.
        
        Scans text_sanitized and case_summary fields.
        Sets possible_named_individual=True if names found.
        """
        text_fields = ["case_summary", "text_sanitized"]
        all_names = []

        for field in text_fields:
            value = record.get(field)
            if value and isinstance(value, str):
                names = self.detect_names(value)
                all_names.extend(names)

        if all_names:
            record["possible_named_individual"] = True
            logger.debug("Possible named individuals detected: {}", all_names[:3])
        else:
            record["possible_named_individual"] = False

        return record
