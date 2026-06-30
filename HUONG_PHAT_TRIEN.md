# 🚀 Lộ Trình Phát Triển ScamShield VN

## Tầm nhìn

Xây dựng **model AI phát hiện lừa đảo trực tuyến** chạy tốt trên local, đóng gói thành SDK/API để tích hợp vào các ứng dụng bảo mật — phục vụ cộng đồng Việt Nam.

---

## Hiện trạng (v0.1 — Baseline)

| Thành phần | Trạng thái | Vấn đề |
|-----------|-----------|--------|
| Pipeline thu thập dữ liệu | ✅ Hoạt động | Đủ dùng |
| Dataset 16,673 records | ✅ Có | Thiếu phishing URLs, thiếu text VN |
| Model XGBoost URL | ⚠️ Baseline | Chỉ dùng url_length, sai trên URL dài hợp lệ |
| Predict script | ✅ Có | Accuracy chưa thực tế |
| Export Kaggle | ✅ PASS 11/11 | OK |

**Vấn đề chính cần giải quyết:**
1. Model chỉ biết 1 feature (url_length) → false positive cao
2. Thiếu dữ liệu phishing URLs (giả mạo ngân hàng, TMĐT)
3. Thiếu dữ liệu text tiếng Việt (tin nhắn scam vs benign)
4. Chưa có inference engine nhẹ cho tích hợp app

---

## Phase 1: Cải thiện Model (2–3 tuần)

### 1.1 Mở rộng feature set cho URL classifier

Thay vì chỉ dùng `url_length`, thêm **20+ features**:

```
URL Structure Features:
├── url_length, path_length, query_length (đã có)
├── domain_length                    ← mới
├── subdomain_count                  ← mới
├── path_depth (số "/" trong path)   ← mới
├── special_char_count (@ % ~ !)    ← mới
├── digit_ratio_in_domain           ← mới
├── has_https (bool)                 ← mới
├── has_port_number (bool)           ← mới
├── has_ip_address (đã có)
├── has_punycode (đã có)
├── has_url_shortener (đã có)
├── tld_is_suspicious (.xyz, .tk, .ml, .top)  ← mới
├── domain_entropy (Shannon entropy) ← mới
├── longest_word_in_path             ← mới
├── brand_in_subdomain (vietcombank, bidv...)  ← mới
├── domain_age_days (nếu có WHOIS)   ← mới
└── alexa_rank_bucket (nếu có Tranco) ← mới
```

### 1.2 Thu thập thêm dữ liệu

| Nguồn | Mục tiêu | Hành động |
|--------|----------|-----------|
| PhishTank | +50K phishing URLs | Đăng ký API key miễn phí |
| Benign URLs thật | +5K | Crawl top 5000 Tranco + Vietnamese sites |
| Phishing VN giả mạo | +500 | Tạo synthetic URLs pattern ngân hàng VN |
| Text scam VN | +500 | Crowdsource từ cộng đồng |
| Text benign VN | +500 | Lấy từ SMS ngân hàng, giao hàng thật |

### 1.3 Retrain model với features mới

```bash
# Sau khi thêm data + features
python notebooks/train_url_classifier.py
```

**Target metrics:**
- Precision ≥ 95% (ít false positive)
- Recall ≥ 90% (bắt được đa số malicious)
- F1 ≥ 92%
- False positive rate trên benign VN domains < 2%

---

## Phase 2: Multi-Model Architecture (1–2 tháng)

### 2.1 Tách thành 3 models chuyên biệt

```
ScamShield VN Models
├── 📦 url_classifier       — XGBoost, phân loại URL malicious/benign
├── 📦 text_classifier      — PhoBERT, phân loại tin nhắn scam/benign  
└── 📦 risk_scorer          — Rule-based + ML, tính risk score 0-100
```

### 2.2 URL Classifier v2 (XGBoost + LightGBM ensemble)

- Dùng 20+ features
- Ensemble 2 models (XGBoost + LightGBM) → voting
- Inference time < 5ms per URL

### 2.3 Vietnamese Text Classifier (PhoBERT fine-tuned)

```python
# Fine-tune trên data benign_messages + scam_cases
from transformers import AutoModelForSequenceClassification
model = AutoModelForSequenceClassification.from_pretrained(
    "vinai/phobert-base", num_labels=3  # scam, suspicious, benign
)
```

- Input: tin nhắn SMS/Zalo/Messenger tiếng Việt
- Output: scam / suspicious / benign + confidence
- Target F1 ≥ 90%

### 2.4 Risk Scorer (tổng hợp)

```python
def compute_risk_score(url=None, text=None) -> int:
    """Trả về risk score 0-100."""
    score = 0
    if url:
        score += url_classifier.predict_proba(url) * 40  # max 40 điểm từ URL
    if text:
        score += text_classifier.predict_proba(text) * 40  # max 40 điểm từ text
    score += rule_based_signals(url, text) * 20  # max 20 điểm từ rules
    return min(100, int(score))
```

---

## Phase 3: Tối ưu Local & Đóng gói (1 tháng)

### 3.1 Tối ưu inference speed

| Mục tiêu | Kỹ thuật |
|-----------|----------|
| URL classifier < 1ms | ONNX Runtime export |
| Text classifier < 50ms | ONNX + quantization INT8 |
| Tổng latency < 100ms | Batch processing, caching |
| RAM < 200MB | Model pruning, shared embeddings |

```python
# Export model sang ONNX cho deployment nhẹ
import onnxmltools
onnx_model = onnxmltools.convert_xgboost(xgb_model)
onnxmltools.save_model(onnx_model, "models/url_classifier.onnx")
```

### 3.2 Đóng gói thành Python package

```
pip install scamshield-vn
```

```python
from scamshield_vn import ScamShield

shield = ScamShield()

# Check URL
result = shield.check_url("https://suspicious-link.xyz")
print(result.risk_level)  # "high" / "medium" / "low"
print(result.confidence)  # 0.94

# Check text message
result = shield.check_text("Tài khoản bị khóa, bấm link để mở khóa...")
print(result.is_scam)     # True
print(result.scam_type)   # "impersonation_bank"
```

### 3.3 Package structure

```
scamshield-vn/
├── scamshield_vn/
│   ├── __init__.py
│   ├── shield.py           # Main API class
│   ├── url_checker.py      # URL analysis
│   ├── text_checker.py     # Text analysis  
│   ├── risk_scorer.py      # Combined scorer
│   ├── models/
│   │   ├── url_classifier.onnx
│   │   ├── text_classifier.onnx
│   │   └── config.json
│   └── utils/
│       ├── features.py
│       └── vietnamese.py
├── pyproject.toml
└── README.md
```

---

## Phase 4: Tích hợp vào App Bảo mật (2–3 tháng)

### 4.1 REST API (cho backend integration)

```python
# FastAPI server
from fastapi import FastAPI
from scamshield_vn import ScamShield

app = FastAPI()
shield = ScamShield()

@app.post("/api/v1/check")
async def check(url: str = None, text: str = None):
    return shield.analyze(url=url, text=text)
```

Deploy options:
- Docker container (self-hosted)
- AWS Lambda / Google Cloud Run (serverless)
- Edge deployment (Cloudflare Workers)

### 4.2 Mobile SDK (Android/iOS)

```kotlin
// Android - Kotlin
val shield = ScamShieldSDK.init(context)
val result = shield.checkUrl("https://...")
if (result.riskLevel == RiskLevel.HIGH) {
    showWarningDialog("Cảnh báo: Link này có dấu hiệu lừa đảo!")
}
```

- ONNX Runtime Mobile cho inference trên device
- Offline mode (không cần internet)
- Model update qua OTA (over-the-air)

### 4.3 Browser Extension

```javascript
// Content script - check mọi link trên page
document.querySelectorAll('a').forEach(link => {
    const result = await scamshield.checkUrl(link.href);
    if (result.riskLevel === 'high') {
        link.classList.add('scamshield-warning');
        link.title = '⚠️ ScamShield: Link đáng ngờ';
    }
});
```

### 4.4 Tích hợp với app banking/fintech

| Partner tiềm năng | Loại tích hợp |
|-------------------|---------------|
| App ngân hàng | Scan URL trước khi mở WebView |
| App ví điện tử | Check deeplink/QR code |
| App nhắn tin | Filter tin nhắn scam |
| Antivirus VN | Plugin phát hiện phishing |
| Trình duyệt Cốc Cốc | Built-in URL checker |

---

## Phase 5: Vận hành & Cải tiến liên tục (ongoing)

### 5.1 Continuous Learning Pipeline

```
User reports → Verify → Add to training data → Retrain weekly → Deploy
```

### 5.2 Monitoring & Feedback loop

- Track false positive/negative rate từ user feedback
- A/B test model versions
- Auto-retrain khi accuracy drop dưới threshold

### 5.3 Threat Intelligence Feed

- Cập nhật URLhaus/PhishTank hàng ngày (đã có collector)
- Realtime blacklist sync
- Community-sourced reports

---

## Tóm tắt Roadmap

```
Hiện tại ──────────────────────────────────────────────── Tương lai

[v0.1 Baseline]  →  [v0.5 Multi-feature]  →  [v1.0 Production]  →  [SDK/API]
  │                    │                        │                      │
  ├─ url_length only   ├─ 20+ features          ├─ ONNX optimized     ├─ pip package
  ├─ 16K records       ├─ 70K+ records          ├─ < 100ms latency    ├─ REST API
  ├─ XGBoost only      ├─ XGBoost + PhoBERT     ├─ < 200MB RAM        ├─ Mobile SDK
  └─ predict.py        └─ 3 models              └─ Docker ready       └─ Browser ext
  
  2 tuần                1-2 tháng                1 tháng                2-3 tháng
```

---

## Bước tiếp theo ngay bây giờ

1. **Đăng ký PhishTank API key** (miễn phí) → thêm 50K phishing URLs
2. **Thêm features** vào `notebooks/train_url_classifier.py` (domain_length, subdomain_count, digit_ratio, tld_suspicious, brand_detection)
3. **Retrain** → đánh giá lại accuracy trên test set đa dạng hơn
4. **Tạo test set thủ công** gồm 50 URL VN hợp lệ + 50 URL lừa đảo VN → benchmark

---

## Ưu thế khi triển khai

| So với giải pháp hiện có | ScamShield VN |
|--------------------------|---------------|
| Google Safe Browsing | Miễn phí, chạy offline, tập trung VN |
| VirusTotal | Không cần API, realtime trên device |
| Kaspersky/Norton | Nhẹ hơn, tùy biến, open-source |
| Không có giải pháp VN | **Đầu tiên** cho thị trường VN |
