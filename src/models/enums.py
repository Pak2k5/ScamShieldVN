"""
Enumeration definitions for the ScamShield VN pipeline.

All enums inherit from (str, Enum) for JSON/YAML serialization compatibility,
allowing direct use of enum values as strings in serialized formats.
"""

from enum import Enum


class SourceType(str, Enum):
    """Classification of data source origin types."""

    OFFICIAL_GOVERNMENT = "official_government"
    THREAT_FEED = "threat_feed"
    NEWS_MEDIA = "news_media"
    COMMUNITY_REPORT = "community_report"
    BENIGN_REFERENCE = "benign_reference"
    INTERNATIONAL_ORGANIZATION = "international_organization"


class CredibilityLevel(str, Enum):
    """Credibility rating assigned to a data source."""

    OFFICIAL = "official"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AccessMethod(str, Enum):
    """Method used to access and retrieve data from a source."""

    PUBLIC_API = "public_api"
    PUBLIC_CSV = "public_csv"
    PUBLIC_RSS = "public_rss"
    PUBLIC_WEBPAGE = "public_webpage"
    MANUAL_CURATED = "manual_curated"
    API_KEY_REQUIRED = "api_key_required"


class RedistributionStatus(str, Enum):
    """Whether redistributing data from a source is permitted."""

    ALLOWED = "allowed"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"


class EvidenceLevel(str, Enum):
    """Strength of evidence supporting a record's classification.

    A = strongest (official confirmation), E = weakest (unverified).
    """

    A = "a"
    B = "b"
    C = "c"
    D = "d"
    E = "e"


class RecordType(str, Enum):
    """Type of record stored in the dataset."""

    URL = "url"
    CASE = "case"
    DOMAIN = "domain"
    MESSAGE = "message"


class Label(str, Enum):
    """Classification label applied to a record."""

    PHISHING_URL = "phishing_url"
    MALWARE_URL = "malware_url"
    SCAM_CASE = "scam_case"
    SCAM_PATTERN = "scam_pattern"
    SUSPICIOUS = "suspicious"
    COMMUNITY_REPORTED_UNVERIFIED = "community_reported_unverified"
    BENIGN_URL = "benign_url"
    BENIGN_MESSAGE = "benign_message"
    UNKNOWN = "unknown"


class ConflictStatus(str, Enum):
    """Status of a detected conflict between data sources."""

    NEEDS_REVIEW = "needs_review"
    RESOLVED = "resolved"


class BenignMessageType(str, Enum):
    """Sub-classification for benign (non-scam) messages."""

    OTP_WARNING = "otp_warning"
    DELIVERY_NOTIFICATION = "delivery_notification"
    BANK_EDUCATION = "bank_education"
    PROMOTION = "promotion"
    SYSTEM_NOTIFICATION = "system_notification"
    OTHER = "other"


class SummaryMethod(str, Enum):
    """Method used to generate a case summary."""

    MANUAL = "manual"
    EXTRACTIVE = "extractive"
    ABSTRACTIVE = "abstractive"
    RULE_BASED = "rule_based"


class RequiresAction(str, Enum):
    """Action required during human review of a record."""

    APPROVE = "approve"
    REJECT = "reject"
    EDIT = "edit"
    ESCALATE = "escalate"


class VerificationMethod(str, Enum):
    """Method used to verify a benign URL or domain."""

    MANUAL_CURATED = "manual_curated"
    TRANCO_RANKING = "tranco_ranking"
    OFFICIAL_REGISTRY = "official_registry"
