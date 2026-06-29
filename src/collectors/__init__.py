"""Data collectors for ScamShield VN pipeline.

Provides a registry mapping source_ids to their collector classes.
"""

from src.collectors.base import BaseCollector
from src.collectors.phishtank import PhishTankCollector
from src.collectors.openphish import OpenPhishCollector
from src.collectors.urlhaus import URLhausCollector
from src.collectors.safe_browsing import SafeBrowsingEnricher
from src.collectors.virustotal import VirusTotalEnricher
from src.collectors.vietnamese_official import VietnameseOfficialCollector
from src.collectors.tin_nhiem_mang import TinNhiemMangCollector
from src.collectors.tranco import TrancoCollector
from src.collectors.benign_domains import BenignDomainsCollector
from src.collectors.benign_messages import BenignMessagesCollector

# Map source_id -> collector class
COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "phishtank_verified": PhishTankCollector,
    "openphish_feed": OpenPhishCollector,
    "urlhaus_malware": URLhausCollector,
    "vietnamese_official": VietnameseOfficialCollector,
    "tin_nhiem_mang": TinNhiemMangCollector,
    "tranco_top1000": TrancoCollector,
    "benign_domains_vn": BenignDomainsCollector,
    "benign_messages": BenignMessagesCollector,
}

# Enrichers (not in the main collector flow, used for post-collection enrichment)
ENRICHER_REGISTRY = {
    "google_safe_browsing": SafeBrowsingEnricher,
    "virustotal": VirusTotalEnricher,
}

__all__ = [
    "BaseCollector",
    "COLLECTOR_REGISTRY",
    "ENRICHER_REGISTRY",
    "PhishTankCollector",
    "OpenPhishCollector",
    "URLhausCollector",
    "SafeBrowsingEnricher",
    "VirusTotalEnricher",
    "VietnameseOfficialCollector",
    "TinNhiemMangCollector",
    "TrancoCollector",
    "BenignDomainsCollector",
    "BenignMessagesCollector",
]
