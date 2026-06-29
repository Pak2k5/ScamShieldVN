"""Curated Vietnamese benign domains collector."""

from datetime import datetime, timezone

from loguru import logger

from src.collectors.base import BaseCollector
from src.models.enums import RecordType
from src.models.record import RawRecord


class BenignDomainsCollector(BaseCollector):
    """Provides curated list of legitimate Vietnamese domains.
    
    Covers: banking, e-wallet, e-commerce, logistics, telecommunications,
    and government domains. Minimum 5 per category.
    """

    # Curated Vietnamese benign domains by category
    DOMAINS = {
        "banking": [
            {"domain": "vietcombank.com.vn", "name": "Vietcombank"},
            {"domain": "bidv.com.vn", "name": "BIDV"},
            {"domain": "techcombank.com.vn", "name": "Techcombank"},
            {"domain": "vpbank.com.vn", "name": "VPBank"},
            {"domain": "acb.com.vn", "name": "ACB"},
            {"domain": "mbbank.com.vn", "name": "MB Bank"},
            {"domain": "tpbank.vn", "name": "TPBank"},
            {"domain": "vib.com.vn", "name": "VIB"},
            {"domain": "sacombank.com.vn", "name": "Sacombank"},
            {"domain": "hdbank.com.vn", "name": "HDBank"},
        ],
        "e_wallet": [
            {"domain": "momo.vn", "name": "MoMo"},
            {"domain": "zalopay.vn", "name": "ZaloPay"},
            {"domain": "vnpay.vn", "name": "VNPAY"},
            {"domain": "viettelpay.vn", "name": "ViettelPay"},
            {"domain": "shopeepay.vn", "name": "ShopeePay"},
        ],
        "e_commerce": [
            {"domain": "shopee.vn", "name": "Shopee"},
            {"domain": "lazada.vn", "name": "Lazada"},
            {"domain": "tiki.vn", "name": "Tiki"},
            {"domain": "sendo.vn", "name": "Sendo"},
            {"domain": "thegioididong.com", "name": "Thế Giới Di Động"},
            {"domain": "dienmayxanh.com", "name": "Điện Máy Xanh"},
        ],
        "logistics": [
            {"domain": "ghn.vn", "name": "Giao Hàng Nhanh"},
            {"domain": "ghtk.vn", "name": "Giao Hàng Tiết Kiệm"},
            {"domain": "vnpost.vn", "name": "Vietnam Post"},
            {"domain": "viettelpost.vn", "name": "Viettel Post"},
            {"domain": "jt-express.vn", "name": "J&T Express"},
        ],
        "telecommunications": [
            {"domain": "viettel.com.vn", "name": "Viettel"},
            {"domain": "mobifone.vn", "name": "MobiFone"},
            {"domain": "vinaphone.com.vn", "name": "VinaPhone"},
            {"domain": "vnpt.com.vn", "name": "VNPT"},
            {"domain": "fpt.com.vn", "name": "FPT Telecom"},
        ],
        "government": [
            {"domain": "chinhphu.vn", "name": "Chính phủ Việt Nam"},
            {"domain": "mic.gov.vn", "name": "Bộ TT&TT"},
            {"domain": "sbv.gov.vn", "name": "Ngân hàng Nhà nước"},
            {"domain": "bocongan.gov.vn", "name": "Bộ Công an"},
            {"domain": "mof.gov.vn", "name": "Bộ Tài chính"},
            {"domain": "dangkykinhdoanh.gov.vn", "name": "Đăng ký kinh doanh"},
        ],
    }

    def collect(self) -> list[RawRecord]:
        """Return curated Vietnamese benign domain records."""
        records = []
        collection_time = datetime.now(timezone.utc)

        for category, domains in self.DOMAINS.items():
            for entry in domains:
                record = RawRecord(
                    source_id=self.source.source_id,
                    collection_timestamp=collection_time,
                    record_type=RecordType.DOMAIN,
                    domain=entry["domain"],
                    category=category,
                    organization_name=entry["name"],
                    verification_method="manual_curated",
                )
                records.append(record)

        logger.info("Loaded {} curated Vietnamese benign domains across {} categories.",
                    len(records), len(self.DOMAINS))
        return records
