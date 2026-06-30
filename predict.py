"""
ScamShield VN - Kiểm Tra Link Lừa Đảo
=======================================
Công cụ kiểm tra URL/link có dấu hiệu lừa đảo, mã độc hay không.

Logic đánh giá:
  1. Tách domain gốc từ URL
  2. Nếu domain thuộc danh sách uy tín → AN TOÀN (bất kể path dài thế nào)
  3. Nếu domain lạ → xét features: TLD, giả mạo brand, IP, keywords đáng ngờ

Sử dụng:
    python predict.py https://link-can-kiem-tra.com
    python predict.py                        (chế độ nhập liên tục)
"""

import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np

MODEL_PATH = Path("models/url_classifier_xgb.joblib")

# ═══════════════════════════════════════════════════════════════════════════════
# DANH SÁCH DOMAIN UY TÍN (Whitelist)
# Nếu domain gốc thuộc danh sách này → AN TOÀN, không cần xét thêm
# ═══════════════════════════════════════════════════════════════════════════════

TRUSTED_DOMAINS = {
    # ── Ngân hàng Việt Nam ──
    "vietcombank.com.vn", "bidv.com.vn", "techcombank.com.vn", "vpbank.com.vn",
    "acb.com.vn", "mbbank.com.vn", "tpbank.vn", "vib.com.vn", "sacombank.com.vn",
    "hdbank.com.vn", "msb.com.vn", "seabank.com.vn", "vietinbank.vn",
    "agribank.com.vn", "shb.com.vn", "namabank.com.vn", "lpbank.com.vn",

    # ── Ví điện tử ──
    "momo.vn", "zalopay.vn", "vnpay.vn", "viettelpay.vn", "shopeepay.vn",

    # ── Sàn TMĐT ──
    "shopee.vn", "lazada.vn", "tiki.vn", "sendo.vn", "thegioididong.com",
    "dienmayxanh.com", "cellphones.com.vn", "fptshop.com.vn", "topzone.vn",
    "bachhoaxanh.com", "hasaki.vn", "tgdd.vn",

    # ── Logistics ──
    "ghn.vn", "ghtk.vn", "vnpost.vn", "viettelpost.vn", "jt-express.vn",
    "ninjavan.co", "spx.vn", "grab.com",

    # ── Nhà mạng ──
    "viettel.com.vn", "mobifone.vn", "vinaphone.com.vn", "vnpt.com.vn",
    "fpt.com.vn", "fpt.vn",

    # ── Cơ quan nhà nước ──
    "chinhphu.vn", "mic.gov.vn", "sbv.gov.vn", "bocongan.gov.vn",
    "mof.gov.vn", "dangkykinhdoanh.gov.vn", "thuevietnam.vn",
    "baohiemxahoi.gov.vn", "dichvucong.gov.vn",

    # ── Báo chí ──
    "vnexpress.net", "tuoitre.vn", "thanhnien.vn", "nhandan.vn",
    "baochinhphu.vn", "dantri.com.vn", "vietnamnet.vn", "kenh14.vn",
    "cafef.vn", "zing.vn", "zingnews.vn",

    # ── Công nghệ / Big Tech ──
    "google.com", "google.com.vn", "facebook.com", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "github.com",
    "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "wikipedia.org", "stackoverflow.com", "reddit.com",

    # ── Giáo dục ──
    "hust.edu.vn", "vnu.edu.vn", "ueh.edu.vn", "hcmus.edu.vn",
    "tdtu.edu.vn", "uit.edu.vn", "bku.edu.vn",

    # ── Khác ──
    "zalo.me", "coccoc.com", "vietcetera.com", "tinhte.vn",
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLD ĐÁ NGỜ — các đuôi domain hay bị lạm dụng cho lừa đảo
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "buzz", "club",
    "work", "click", "link", "info", "icu", "cam", "monster",
    "rest", "hair", "sbs", "cfd",
}

# ═══════════════════════════════════════════════════════════════════════════════
# BRANDS THƯỜNG BỊ GIẢ MẠO
# ═══════════════════════════════════════════════════════════════════════════════

BRANDS = [
    "vietcombank", "techcombank", "bidv", "vpbank", "acb", "mbbank", "tpbank",
    "agribank", "vietinbank", "sacombank", "momo", "zalopay", "vnpay",
    "shopee", "lazada", "tiki", "grab", "facebook", "google", "zalo",
    "apple", "microsoft", "samsung", "viettel", "mobifone", "vinaphone",
]

# ═══════════════════════════════════════════════════════════════════════════════
# KEYWORDS ĐÁNG NGỜ TRONG PATH
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "password", "credential", "authenticate",
    "wallet", "transfer", "payment", "billing", "invoice",
    "suspended", "locked", "unusual", "verify-identity",
    "otp", "pin", "token",
}


def get_domain_root(url: str) -> str:
    """Tách domain gốc (registered domain) từ URL.
    
    https://www.topzone.vn/tekzone/abc → topzone.vn
    https://sub.vietcombank.com.vn/page → vietcombank.com.vn
    """
    try:
        import tldextract
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except ImportError:
        # Fallback nếu không có tldextract
        parsed = urlparse(url)
        netloc = parsed.netloc or ""
        # Bỏ www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc


def check_brand_impersonation(domain: str) -> str | None:
    """Kiểm tra domain có giả mạo brand nào không.
    
    Ví dụ: vietcombank-secure.xyz → giả mạo 'vietcombank'
    """
    domain_lower = domain.lower()
    for brand in BRANDS:
        if brand in domain_lower:
            # Brand xuất hiện trong domain NHƯNG domain không phải chính chủ
            official_domains = [d for d in TRUSTED_DOMAINS if brand in d]
            if domain not in TRUSTED_DOMAINS:
                return brand
    return None


def analyze_url(url: str) -> dict:
    """Phân tích URL và trả về điểm nguy hiểm 0-100.
    
    Logic:
      1. Domain thuộc whitelist → 0 điểm (an toàn)
      2. Domain lạ → tính điểm từ nhiều yếu tố
    """
    parsed = urlparse(url)
    domain_full = parsed.netloc or ""
    domain_root = get_domain_root(url)
    path = parsed.path.lower()
    
    # ── BƯỚC 1: Kiểm tra domain uy tín ──
    is_trusted = domain_root in TRUSTED_DOMAINS
    
    # Cũng check nếu domain kết thúc bằng .gov.vn hoặc .edu.vn
    if domain_full.endswith(".gov.vn") or domain_full.endswith(".edu.vn"):
        is_trusted = True
    
    if is_trusted:
        return {
            "url": url,
            "domain_root": domain_root,
            "is_trusted": True,
            "score": 0,
            "reasons": ["Domain thuộc danh sách uy tín đã xác minh"],
        }
    
    # ── BƯỚC 2: Domain không thuộc whitelist → tính điểm nguy hiểm ──
    score = 30  # Bắt đầu từ 30 (domain không xác minh = có rủi ro cơ bản)
    reasons = []
    
    # Kiểm tra TLD đáng ngờ
    tld = domain_root.split(".")[-1] if "." in domain_root else ""
    if tld in SUSPICIOUS_TLDS:
        score += 25
        reasons.append(f"Đuôi domain .{tld} thường bị lạm dụng cho lừa đảo")
    
    # Kiểm tra giả mạo brand
    impersonated = check_brand_impersonation(domain_root)
    if impersonated:
        score += 30
        reasons.append(f"Nghi giả mạo thương hiệu '{impersonated}' (domain không chính chủ)")
    
    # Kiểm tra IP thay vì domain
    if any(c.isdigit() for c in domain_full.split(".")) and all(
        part.isdigit() for part in domain_full.split(".") if part
    ):
        score += 20
        reasons.append("Sử dụng địa chỉ IP thay vì tên miền")
    
    # Kiểm tra punycode
    if "xn--" in domain_full:
        score += 15
        reasons.append("Sử dụng punycode (có thể giả mạo ký tự)")
    
    # Kiểm tra keywords đáng ngờ trong path
    suspicious_found = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path]
    if suspicious_found:
        score += min(20, len(suspicious_found) * 7)
        reasons.append(f"Path chứa từ khóa đáng ngờ: {', '.join(suspicious_found[:3])}")
    
    # Kiểm tra URL shortener
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd"}
    if domain_full in shorteners:
        score += 15
        reasons.append("Link rút gọn — không biết đích đến thực sự")
    
    # Nếu không có lý do cụ thể nào, giảm điểm base
    if not reasons:
        score = 25
        reasons.append("Domain không nằm trong danh sách đã xác minh")
    
    # Giới hạn 0-100
    score = max(0, min(100, score))
    
    return {
        "url": url,
        "domain_root": domain_root,
        "is_trusted": False,
        "score": score,
        "reasons": reasons,
    }


def get_verdict(score: float, is_trusted: bool = False) -> dict:
    """Đưa ra kết luận và lời khuyên dựa trên điểm đánh giá."""
    
    if is_trusted or score <= 20:
        return {
            "level": "AN TOÀN",
            "icon": "✅",
            "color_bar": "🟢🟢🟢🟢🟢",
            "summary": "Link này thuộc nguồn uy tín đã được xác minh.",
            "advice": "Bạn có thể truy cập bình thường. Domain này nằm trong danh sách website đáng tin cậy.",
        }
    elif score <= 40:
        return {
            "level": "CHƯA XÁC MINH",
            "icon": "❓",
            "color_bar": "🟡🟡⚪⚪⚪",
            "summary": "Link này từ nguồn chưa được xác minh.",
            "advice": (
                "Lời khuyên:\n"
                "  • Domain này không nằm trong danh sách uy tín đã biết\n"
                "  • Không nhất thiết là lừa đảo, nhưng hãy cẩn thận\n"
                "  • Không nhập mật khẩu hoặc thông tin ngân hàng nếu không chắc chắn"
            ),
        }
    elif score <= 60:
        return {
            "level": "CẦN CẨN THẬN",
            "icon": "⚠️",
            "color_bar": "🟡🟡🟡🟡⚪",
            "summary": "Link này có dấu hiệu đáng ngờ.",
            "advice": (
                "Lời khuyên:\n"
                "  • Không nhập mật khẩu, OTP, hoặc thông tin ngân hàng\n"
                "  • Kiểm tra lại tên miền có đúng chính tả không\n"
                "  • Nếu nhận từ người lạ qua SMS/Zalo → nên bỏ qua\n"
                "  • Truy cập trực tiếp website chính thức thay vì bấm link"
            ),
        }
    elif score <= 80:
        return {
            "level": "NGHI NGỜ CAO",
            "icon": "🔶",
            "color_bar": "🟠🟠🟠🟠⚪",
            "summary": "Link này có nhiều dấu hiệu của link lừa đảo.",
            "advice": (
                "Lời khuyên:\n"
                "  • KHÔNG nên truy cập link này\n"
                "  • KHÔNG nhập bất kỳ thông tin cá nhân nào\n"
                "  • Nếu link tự xưng \"ngân hàng\" → rất có thể giả mạo\n"
                "  • Hãy truy cập trực tiếp app/website chính thức"
            ),
        }
    else:
        return {
            "level": "NGUY HIỂM",
            "icon": "🚨",
            "color_bar": "🔴🔴🔴🔴🔴",
            "summary": "Link này gần như chắc chắn là lừa đảo hoặc chứa mã độc!",
            "advice": (
                "Lời khuyên:\n"
                "  • TUYỆT ĐỐI KHÔNG truy cập link này\n"
                "  • KHÔNG tải file hoặc cài đặt bất kỳ thứ gì\n"
                "  • KHÔNG cung cấp OTP, mật khẩu, số tài khoản\n"
                "  • Nếu đã lỡ bấm → đổi mật khẩu ngay, kiểm tra tài khoản ngân hàng\n"
                "  • Báo cáo tại: https://canhbao.khonggianmang.gov.vn"
            ),
        }


def print_result(result: dict):
    """In kết quả đánh giá bằng tiếng Việt."""
    score = result["score"]
    verdict = get_verdict(score, result.get("is_trusted", False))

    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           🛡️  SCAMSHIELD VN - KẾT QUẢ ĐÁNH GIÁ            ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Link: {result['url'][:52]}")
    if len(result['url']) > 52:
        print(f"║        {result['url'][52:104]}")
        if len(result['url']) > 104:
            print(f"║        {result['url'][104:]}")
    print("║")
    print(f"║  Domain gốc:       {result['domain_root']}")
    
    if result.get("is_trusted"):
        print(f"║  Trạng thái domain: 🏛️  THUỘC DANH SÁCH UY TÍN")
    else:
        print(f"║  Trạng thái domain: ❓ CHƯA XÁC MINH")
    
    print("║")
    print(f"║  Mức độ nguy hiểm: {verdict['color_bar']}")
    print(f"║  Điểm đánh giá:    {score:.0f}/100")
    print(f"║  Kết luận:         {verdict['icon']} {verdict['level']}")
    print("║")
    print(f"║  {verdict['summary']}")
    
    # In lý do đánh giá
    if result.get("reasons"):
        print("║")
        print("║  Phân tích chi tiết:")
        for reason in result["reasons"]:
            print(f"║    • {reason}")
    
    print("║")
    print("║  ───────────────────────────────────────────────────────────")
    for line in verdict["advice"].split("\n"):
        print(f"║  {line}")
    print("║")
    print("║  Thang điểm: 0-20 An toàn | 21-40 Chưa xác minh")
    print("║              41-60 Cẩn thận | 61-80 Nghi ngờ | 81-100 Nguy hiểm")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()


def main():
    print()
    print("  🛡️  ScamShield VN — Công cụ kiểm tra link lừa đảo")
    print("  ─────────────────────────────────────────────────────")
    print("  Phiên bản: 0.2.0 (domain trust + rule-based)")
    print("  Logic: Xác minh domain gốc trước → phân tích features nếu lạ")
    print()

    # Nếu có URL từ command line
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        result = analyze_url(url)
        print_result(result)
        return

    # Chế độ interactive
    print("  Nhập link cần kiểm tra (gõ 'thoat' để dừng):")
    print()

    while True:
        try:
            url = input("  🔍 Nhập link: ").strip()
            if url.lower() in ("thoat", "quit", "exit", "q", "thoát"):
                print("\n  👋 Tạm biệt! Hãy cẩn thận với link lạ nhé.\n")
                break
            if not url:
                continue
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            result = analyze_url(url)
            print_result(result)
        except KeyboardInterrupt:
            print("\n\n  👋 Tạm biệt!\n")
            break


if __name__ == "__main__":
    main()
