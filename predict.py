"""
ScamShield VN - URL Checker
============================
Kiểm tra URL có phải malicious hay không.

Sử dụng:
    python predict.py https://example.com
    python predict.py                        (chế độ interactive)
"""

import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np

MODEL_PATH = Path("models/url_classifier_xgb.joblib")


def extract_features(url: str) -> dict:
    """Trích xuất features từ URL."""
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
    """Dự đoán URL có malicious hay không."""
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
    
    return {
        "url": url,
        "is_malicious": bool(prediction),
        "label": "🚨 MALICIOUS" if prediction else "✅ BENIGN",
        "confidence": float(max(probability)),
        "malicious_prob": float(probability[1]),
        "benign_prob": float(probability[0]),
        "features": features,
    }


def print_result(result: dict):
    """In kết quả đẹp."""
    print(f"\n{'='*50}")
    print(f"  URL: {result['url']}")
    print(f"  Kết quả: {result['label']}")
    print(f"  Confidence: {result['confidence']*100:.1f}%")
    print(f"  P(malicious): {result['malicious_prob']*100:.1f}%")
    print(f"  P(benign): {result['benign_prob']*100:.1f}%")
    print(f"{'='*50}")


def main():
    # Load model
    if not MODEL_PATH.exists():
        print("❌ Model chưa train! Chạy trước:")
        print("   python notebooks/train_url_classifier.py")
        sys.exit(1)

    model = joblib.load(MODEL_PATH)
    print("🛡️  ScamShield VN - URL Checker")
    print("   Model loaded successfully.\n")

    # Nếu có URL từ command line
    if len(sys.argv) > 1:
        url = sys.argv[1]
        result = predict_url(model, url)
        print_result(result)
        return

    # Chế độ interactive
    print("   Nhập URL để kiểm tra (gõ 'quit' để thoát):\n")
    while True:
        try:
            url = input("🔍 URL: ").strip()
            if url.lower() in ("quit", "exit", "q"):
                print("\n👋 Bye!")
                break
            if not url:
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            result = predict_url(model, url)
            print_result(result)
            print()
        except KeyboardInterrupt:
            print("\n👋 Bye!")
            break


if __name__ == "__main__":
    main()
