# 🚀 Đề Xuất Hướng Phát Triển ScamShield VN

## Tầm nhìn

Biến ScamShield VN từ một bộ dữ liệu nghiên cứu thành **hệ sinh thái phát hiện lừa đảo trực tuyến** phục vụ cộng đồng Việt Nam — bao gồm dataset, mô hình AI, API, và ứng dụng thực tế.

---

## Giai đoạn 1: Mở rộng Dataset (1–2 tháng)

### 1.1 Tăng quy mô dữ liệu

| Mục tiêu | Hiện tại | Target |
|-----------|----------|--------|
| Malware URLs | 0 (sẵn collector) | 50,000+ từ URLhaus |
| Phishing URLs | 0 (sẵn collector) | 20,000+ từ PhishTank + OpenPhish |
| Benign domains VN | 37 | 200+ (thêm ngân hàng, fintech, startup) |
| Benign messages | 25 | 500+ (crowdsource từ cộng đồng) |
| Vietnamese scam cases | 10 seeds | 500+ cases từ báo chí/cơ quan |
| Tranco benign | 0 (sẵn collector) | 1,000 domains |

### 1.2 Thêm nguồn dữ liệu mới

- **Báo chí tự động**: Parser cho VnExpress, Tuổi Trẻ, Thanh Niên (chỉ lấy metadata + paraphrase)
- **Ngân hàng warnings**: Trang cảnh báo lừa đảo của Vietcombank, BIDV, Techcombank
- **Community reports**: Form cho người dùng gửi tin nhắn/URL đáng ngờ (có consent)
- **Telegram scam channels**: Thu thập public channels lừa đảo (nếu pháp lý cho phép)

### 1.3 Nâng cao chất lượng nhãn

- Thuê 3–5 annotators tiếng Việt review evidence C/D/E records
- Xây annotation tool đơn giản (Streamlit/Gradio) để review queue
- Inter-annotator agreement (IAA) đạt ≥ 0.8 Cohen's Kappa

---

## Giai đoạn 2: Xây dựng mô hình AI (2–4 tháng)

### 2.1 URL Phishing Classifier

**Input**: URL features (length, TLD, has_ip, has_punycode, domain_hash...)  
**Output**: phishing / malware / benign  
**Approach**: 
- Gradient Boosting (XGBoost/LightGBM) cho baseline
- Deep learning (CNN trên character-level URL)
- Đạt target: F1 ≥ 0.95 trên test set

### 2.2 Vietnamese Scam Text Classifier

**Input**: Tin nhắn SMS/Zalo/Messenger tiếng Việt  
**Output**: scam / suspicious / benign  
**Approach**:
- Fine-tune PhoBERT (pre-trained Vietnamese BERT) trên benign_messages + scam cases
- Kết hợp rule-based risk signals + neural
- Target: F1 ≥ 0.90 cho scam detection

### 2.3 Scam Type Classifier (Multi-label)

**Input**: Text/URL + context  
**Output**: 1–5 scam types từ taxonomy 18 loại  
**Approach**: Multi-label classification với PhoBERT + sigmoid heads

### 2.4 Risk Signal Extractor

**Input**: Tin nhắn tiếng Việt  
**Output**: List risk signals (otp_request, urgency_pressure, impersonation_claim...)  
**Approach**: Named Entity Recognition (NER) style hoặc multi-label

---

## Giai đoạn 3: API và Tích hợp (3–6 tháng)

### 3.1 ScamShield API

REST API cho phép kiểm tra URL/tin nhắn:

```
POST /api/v1/check-url
{
  "url": "https://suspicious-site.xyz/login"
}

Response:
{
  "risk_level": "high",
  "label": "phishing_url",
  "confidence": 0.94,
  "risk_signals": ["spoofed_brand_domain", "impersonation_bank"],
  "recommendation": "Không truy cập link này"
}
```

```
POST /api/v1/check-message
{
  "text": "Tài khoản bạn bị khóa. Bấm link để xác minh...",
  "language": "vi"
}

Response:
{
  "risk_level": "high",
  "label": "scam_case",
  "scam_type": "impersonation_bank",
  "risk_signals": ["urgency_pressure", "account_lock_claim", "unknown_url"],
  "confidence": 0.91
}
```

### 3.2 Browser Extension

- Chrome/Firefox extension cảnh báo khi người dùng truy cập URL đáng ngờ
- Hiển thị risk level trên từng link
- Cho phép report URL mới

### 3.3 Chatbot cảnh báo

- Zalo Official Account hoặc Telegram Bot
- Người dùng forward tin nhắn đáng ngờ → bot phản hồi risk assessment
- Tích hợp với API ở trên

### 3.4 Mobile SDK

- Android/iOS SDK cho ứng dụng banking, e-commerce
- Real-time URL scanning trước khi người dùng click
- SMS/notification filtering

---

## Giai đoạn 4: Cộng đồng và Hợp tác (6–12 tháng)

### 4.1 Kaggle Competition

- Tổ chức competition "Vietnamese Scam Detection" trên Kaggle
- Prize pool từ sponsor (ngân hàng, fintech)
- Thu hút researcher quốc tế và Việt Nam

### 4.2 Đối tác chiến lược

| Đối tác | Giá trị mang lại |
|---------|-----------------|
| **Ngân hàng (VCB, BIDV, TCB)** | Dữ liệu scam case thực, sponsor, API integration |
| **Nhà mạng (Viettel, VNPT)** | SMS spam data, user reach |
| **Bộ TT&TT / Cục ATTT** | Legitimacy, taxonomy chính thức, data sharing |
| **VNPay / MoMo / ZaloPay** | Payment fraud patterns, API distribution |
| **Shopee / Lazada** | E-commerce scam patterns |
| **Cảnh sát mạng A05** | Case studies, verification |

### 4.3 Open Source Community

- Publish models lên HuggingFace: `scamshield-vn/phobert-scam-detector`
- Tạo pip package: `pip install scamshield-vn`
- Đóng góp vào Vietnamese NLP ecosystem

### 4.4 Research Papers

- Paper 1: "ScamShield VN: A Multi-Source Dataset for Vietnamese Online Scam Detection"
- Paper 2: "PhoBERT-Scam: Fine-tuning Vietnamese BERT for Scam Text Classification"
- Submit tại: EMNLP, ACL, hoặc conferences Cybersecurity (ACSAC, CCS)

---

## Giai đoạn 5: Sản phẩm hóa (12+ tháng)

### 5.1 ScamShield VN Platform

Web platform hoàn chỉnh:
- Dashboard real-time hiển thị scam trends Việt Nam
- Search engine cho URL/domain lookup
- Community reporting system
- Automated alert system cho ngân hàng/doanh nghiệp

### 5.2 Mô hình kinh doanh bền vững

| Tier | Đối tượng | Pricing |
|------|-----------|---------|
| **Free** | Cá nhân, sinh viên | API 100 requests/ngày |
| **Pro** | Doanh nghiệp nhỏ | API 10K requests/ngày, $49/tháng |
| **Enterprise** | Ngân hàng, fintech | Unlimited API, custom models, SLA |
| **Research** | Đại học, viện NC | Free dataset + API |

### 5.3 Social Impact

- Giảm thiểu thiệt hại lừa đảo trực tuyến tại Việt Nam
- Nâng cao nhận thức cộng đồng
- Hỗ trợ cơ quan chức năng phát hiện sớm chiến dịch scam mới

---

## Roadmap tổng hợp

```
Q3 2024: Dataset v1.0 (50K+ records) + Kaggle publish
Q4 2024: PhoBERT Scam Classifier + API prototype
Q1 2025: Browser Extension + Chatbot beta
Q2 2025: Partnership ngân hàng/nhà mạng
Q3 2025: Kaggle Competition + Research paper
Q4 2025: Platform launch + Enterprise tier
```

---

## Tech Stack đề xuất cho giai đoạn sau

| Layer | Công nghệ |
|-------|-----------|
| ML Training | PyTorch, HuggingFace Transformers, PhoBERT |
| API Backend | FastAPI, Redis, PostgreSQL |
| Browser Extension | TypeScript, Chrome Extension API |
| Mobile SDK | Kotlin (Android), Swift (iOS) |
| Infrastructure | Docker, Kubernetes, AWS/GCP |
| Monitoring | Grafana, Prometheus |
| CI/CD | GitHub Actions |

---

## Ưu thế cạnh tranh

1. **Đặc thù Việt Nam**: Không có tool nào tập trung Vietnamese scam patterns + tiếng Việt NLP
2. **Open-source first**: Dataset + model public → cộng đồng đóng góp
3. **Legal compliance**: Xây từ đầu với privacy/legal framework chặt chẽ
4. **Multi-source**: Kết hợp threat feeds quốc tế + nguồn Việt Nam chính thống
5. **Production-ready pipeline**: Có thể scale lên real-time processing

---

## Rủi ro và giảm thiểu

| Rủi ro | Giảm thiểu |
|--------|------------|
| Thiếu dữ liệu tiếng Việt labeled | Crowdsource + partner ngân hàng |
| False positive cao (block nhầm) | Human-in-the-loop + confidence threshold |
| Scammer thay đổi chiến thuật | Continuous learning + community reports |
| Pháp lý khi public dataset | Đã có legal framework từ M1 (PII, redistribution, evidence) |
| Funding | Start miễn phí → Enterprise revenue → Grant/sponsor |

---

## Kết luận

ScamShield VN có tiềm năng trở thành **nền tảng phát hiện lừa đảo trực tuyến đầu tiên tập trung cho thị trường Việt Nam**. Với dataset chất lượng + mô hình AI + API mở, dự án có thể bảo vệ hàng triệu người dùng Việt Nam khỏi các chiến dịch lừa đảo ngày càng tinh vi.

Bước tiếp theo ngay bây giờ: **Thu thập thêm dữ liệu → Train PhoBERT → Publish Kaggle.**
