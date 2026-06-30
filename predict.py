"""
ScamShield VN - Kiểm Tra Link Lừa Đảo
=======================================
Công cụ kiểm tra URL/link có dấu hiệu lừa đảo, mã độc hay không.

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


def extract_features(url: str) -> dict:
    """Trích xuất đặc trưng từ URL."""
    parsed = urlparse(url)
    domain = parsed.netloc or ""

    features = {
        "url_length": len(url),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "has_ip_address": 1 if any(c.isdigit() for c in domain.split(".")) and domain.replace(".", "").isdigit() else 0,
        "has_punycode": 1 if "xn--" in domain else 0,
        "has_url_shortener": 1 if domain in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd"} else 0,
    }
    return features


def predict_url(model, url: str) -> dict:
    """Dự đoán mức độ nguy hiểm của URL."""
    features = extract_features(url)
    X = np.array([[
        features["url_length"],
        features["path_length"],
        features["query_length"],
        features["has_ip_address"],
        features["has_punycode"],
        features["has_url_shortener"],
    ]])

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]
    malicious_score = float(probability[1]) * 100  # Điểm nguy hiểm 0-100

    return {
        "url": url,
        "is_malicious": bool(prediction),
        "score": malicious_score,
        "features": features,
    }


def get_verdict(score: float) -> dict:
    """Đưa ra kết luận và lời khuyên dựa trên điểm đánh giá.
    
    Thang điểm:
        0-20:   An toàn
        21-50:  Cần cẩn thận
        51-75:  Nghi ngờ cao
        76-100: Nguy hiểm
    """
    if score <= 20:
        return {
            "level": "AN TOÀN",
            "icon": "✅",
            "color_bar": "🟢🟢🟢🟢🟢",
            "summary": "Link này có vẻ an toàn.",
            "advice": "Bạn có thể truy cập bình thường. Tuy nhiên, luôn cẩn thận khi nhập thông tin cá nhân trên bất kỳ website nào.",
        }
    elif score <= 50:
        return {
            "level": "CẦN CẨN THẬN",
            "icon": "⚠️",
            "color_bar": "🟡🟡🟡⚪⚪",
            "summary": "Link này có một số dấu hiệu đáng ngờ.",
            "advice": (
                "Lời khuyên:\n"
                "  • Không nhập mật khẩu, OTP, hoặc thông tin ngân hàng trên link này\n"
                "  • Kiểm tra lại tên miền có đúng chính tả không\n"
                "  • Nếu nhận từ người lạ qua SMS/Zalo → nên bỏ qua"
            ),
        }
    elif score <= 75:
        return {
            "level": "NGHI NGỜ CAO",
            "icon": "🔶",
            "color_bar": "🟠🟠🟠🟠⚪",
            "summary": "Link này có nhiều dấu hiệu giống link lừa đảo/mã độc.",
            "advice": (
                "Lời khuyên:\n"
                "  • KHÔNG nên truy cập link này\n"
                "  • KHÔNG nhập bất kỳ thông tin cá nhân nào\n"
                "  • Nếu link đến từ \"ngân hàng\" hoặc \"cơ quan nhà nước\" → rất có thể giả mạo\n"
                "  • Hãy truy cập trực tiếp website chính thức thay vì bấm link"
            ),
        }
    else:
        return {
            "level": "NGUY HIỂM",
            "icon": "🚨",
            "color_bar": "🔴🔴🔴🔴🔴",
            "summary": "Link này có xác suất rất cao là link lừa đảo hoặc chứa mã độc!",
            "advice": (
                "Lời khuyên:\n"
                "  • TUYỆT ĐỐI KHÔNG truy cập link này\n"
                "  • KHÔNG tải file hoặc cài đặt bất kỳ thứ gì từ link\n"
                "  • KHÔNG cung cấp OTP, mật khẩu, số tài khoản\n"
                "  • Nếu đã lỡ bấm vào → đổi mật khẩu ngay, kiểm tra tài khoản ngân hàng\n"
                "  • Có thể báo cáo link này tại: https://canhbao.khonggianmang.gov.vn"
            ),
        }


def print_result(result: dict):
    """In kết quả đánh giá bằng tiếng Việt, dễ hiểu."""
    score = result["score"]
    verdict = get_verdict(score)

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         🛡️  SCAMSHIELD VN - KẾT QUẢ ĐÁNH GIÁ          ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Link: {result['url'][:50]}")
    if len(result['url']) > 50:
        print(f"║        {result['url'][50:]}")
    print("║")
    print(f"║  Mức độ nguy hiểm: {verdict['color_bar']}")
    print(f"║  Điểm đánh giá:    {score:.0f}/100")
    print(f"║  Kết luận:         {verdict['icon']} {verdict['level']}")
    print("║")
    print(f"║  {verdict['summary']}")
    print("║")
    print("║  ─────────────────────────────────────────────────────")
    for line in verdict["advice"].split("\n"):
        print(f"║  {line}")
    print("║")
    print("║  Thang điểm: 0-20 An toàn | 21-50 Cẩn thận")
    print("║              51-75 Nghi ngờ | 76-100 Nguy hiểm")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def main():
    # Load model
    if not MODEL_PATH.exists():
        print("❌ Chưa có model! Hãy chạy lệnh sau để train model trước:")
        print("   python notebooks/train_url_classifier.py")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    print()
    print("  🛡️  ScamShield VN — Công cụ kiểm tra link lừa đảo")
    print("  ─────────────────────────────────────────────────────")
    print("  Phiên bản: 0.1.0 (baseline)")
    print("  Lưu ý: Model đang ở giai đoạn phát triển, kết quả")
    print("  chỉ mang tính tham khảo. Luôn cẩn thận với link lạ.")
    print()

    # Nếu có URL từ command line
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        result = predict_url(model, url)
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

            result = predict_url(model, url)
            print_result(result)
        except KeyboardInterrupt:
            print("\n\n  👋 Tạm biệt!\n")
            break


if __name__ == "__main__":
    main()
