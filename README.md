<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/License-CC--BY--4.0-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Kaggle-20BEFF?style=for-the-badge&logo=kaggle&logoColor=white" />
</p>

# 🛡️ ScamShield VN

### Vietnamese Online Scam & Phishing Detection Dataset Pipeline

> Bộ công cụ Python CLI tự động thu thập, xử lý, gắn nhãn và xuất bộ dữ liệu phát hiện lừa đảo trực tuyến tại Việt Nam — phục vụ nghiên cứu AI/ML và bảo vệ cộng đồng.

---

## 📋 Mục lục

- [Tổng quan](#-tổng-quan)
- [Tính năng chính](#-tính-năng-chính)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Cài đặt](#-cài-đặt)
- [Sử dụng](#-sử-dụng)
- [Pipeline xử lý 10 bước](#-pipeline-xử-lý-10-bước)
- [Nguồn dữ liệu](#-nguồn-dữ-liệu)
- [Schema dữ liệu](#-schema-dữ-liệu)
- [Kaggle Publication Gate](#-kaggle-publication-gate)
- [Bảo mật & Đạo đức](#-bảo-mật--đạo-đức)
- [Đóng góp](#-đóng-góp)
- [License](#-license)

---

## 🎯 Tổng quan

**ScamShield VN** là một data pipeline hoàn chỉnh giải quyết bài toán: *"Làm sao tạo được bộ dữ liệu chất lượng để train AI phát hiện lừa đảo trực tuyến tại Việt Nam?"*

### Vấn đề
- Lừa đảo trực tuyến tại Việt Nam tăng mạnh (24 hình thức theo Cục ATTT)
- Thiếu dataset tiếng Việt có nhãn chất lượng cho nghiên cứu
- Dữ liệu phân tán, không có provenance rõ ràng
- Rủi ro PII khi public dataset

### Giải pháp
Pipeline tự động với 3 tầng dữ liệu an toàn:

```
[Thu thập] → [Xử lý 10 bước] → [Xuất Kaggle-ready]
     ↓              ↓                    ↓
 private_raw   processed_private    public_kaggle
 (thô, PII)    (labeled, masked)   (an toàn, public)
```

---

## ✨ Tính năng chính

| Tính năng | Mô tả |
|-----------|--------|
| 🔍 **Multi-source Collection** | Thu thập từ 10+ nguồn (URLhaus, PhishTank, OpenPhish, Tranco, nguồn VN) |
| 🏷️ **Auto Labeling** | Gắn nhãn tự động: phishing_url, malware_url, benign_url, scam_case... |
| 📊 **Evidence Scoring** | Đánh giá mức tin cậy A/B/C/D/E dựa trên nguồn |
| 🔒 **PII Masking** | Tự động ẩn SĐT, CCCD, email, STK ngân hàng, OTP |
| 👤 **Named Entity Detection** | Phát hiện tên người Việt trong text |
| ⚔️ **Conflict Detection** | Phát hiện xung đột benign vs malicious |
| 📝 **Review Queue** | Đưa record không chắc chắn vào hàng chờ human review |
| ✅ **11-Point Kaggle Gate** | Kiểm tra tự động trước khi publish |
| 📦 **Multi-format Export** | CSV, JSONL, Parquet, Excel |
| 🇻🇳 **Vietnamese Taxonomy** | 18 loại lừa đảo phổ biến tại Việt Nam |

---

## 🏗️ Kiến trúc hệ thống

```
┌──────────────────────────────────────────────────────────────┐
│                    CLI Layer (src/main.py)                     │
│         collect | process | export | validate | run           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ COLLECTORS  │  │  PROCESSORS  │  │     EXPORTERS      │  │
│  │             │  │              │  │                    │  │
│  │ PhishTank   │  │ 1. Cleaner   │  │ Private Raw (JSONL)│  │
│  │ OpenPhish   │  │ 2. Labeler   │  │ Processed (CSV/    │  │
│  │ URLhaus     │  │ 3. Evidence  │  │   JSONL/Parquet)   │  │
│  │ SafeBrowsing│  │ 4. Dedup     │  │ Public Kaggle      │  │
│  │ VirusTotal  │  │ 5. Conflict  │  │ Excel Metadata     │  │
│  │ VN Official │  │ 6. PII Mask  │  │ README/Card/License│  │
│  │ TinNhiemMang│  │ 7. NER       │  │ Manifest           │  │
│  │ Tranco      │  │ 8. Review Q  │  │                    │  │
│  │ Benign VN   │  │ 9. PubSafety │  └────────────────────┘  │
│  │ Benign Msgs │  │10. TrainReady│                           │
│  └─────────────┘  └──────────────┘  ┌────────────────────┐  │
│                                      │    VALIDATORS      │  │
│  ┌─────────────┐                     │                    │  │
│  │   CONFIG    │                     │ PII Validator      │  │
│  │             │                     │ Redistribution     │  │
│  │ sources.yaml│                     │ Private Leak Check │  │
│  │ pipeline.yaml                     │ Kaggle Gate (11pt) │  │
│  │ taxonomy.yaml                     │ Quality Report     │  │
│  │ pii_patterns│                     └────────────────────┘  │
│  └─────────────┘                                             │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 Cấu trúc dự án

```
ScamShieldVN/
├── 📄 README.md                    # File này
├── 📄 HUONG_DAN_SU_DUNG.md        # Hướng dẫn sử dụng chi tiết
├── 📄 HUONG_PHAT_TRIEN.md         # Đề xuất phát triển
├── 📄 pyproject.toml               # Project metadata & dependencies
├── 📄 requirements.txt             # Pinned dependencies
├── 📄 .env.example                 # Template API keys
├── 📄 .gitignore                   # Bảo vệ private data
│
├── 📂 config/                      # Cấu hình pipeline
│   ├── sources.yaml                # Registry 10 nguồn dữ liệu
│   ├── pipeline.yaml               # Cấu hình pipeline (rate limit, retry...)
│   ├── taxonomy_seed.yaml          # 18 loại lừa đảo tiếng Việt
│   ├── vietnamese_sources.yaml     # Seed URLs nguồn VN chính thức
│   └── pii_patterns.yaml           # Regex patterns phát hiện PII
│
├── 📂 src/                         # Source code chính
│   ├── main.py                     # Entry point + subcommand dispatch
│   ├── cli.py                      # CLI argument parser
│   ├── 📂 config/                  # Config loaders
│   │   ├── registry.py             # YAML source registry loader
│   │   ├── settings.py             # Pipeline config loader
│   │   └── env.py                  # .env + environment variables
│   ├── 📂 models/                  # Pydantic data models
│   │   ├── enums.py                # 12 enum definitions
│   │   ├── source.py               # SourceEntry + SourceRegistry
│   │   ├── record.py               # RawRecord, ProcessedRecord, PublicRecord
│   │   ├── review.py               # ReviewQueueRecord
│   │   └── manifest.py             # DataManifest
│   ├── 📂 collectors/              # Data collectors (10 sources)
│   │   ├── base.py                 # Abstract BaseCollector
│   │   ├── phishtank.py            # PhishTank phishing URLs
│   │   ├── openphish.py            # OpenPhish feed
│   │   ├── urlhaus.py              # URLhaus malware URLs (CC0)
│   │   ├── safe_browsing.py        # Google Safe Browsing enrichment
│   │   ├── virustotal.py           # VirusTotal enrichment
│   │   ├── vietnamese_official.py  # VN government sources (seed-based)
│   │   ├── tin_nhiem_mang.py       # Tín Nhiệm Mạng
│   │   ├── tranco.py               # Tranco top 1000 domains
│   │   ├── benign_domains.py       # 37 curated VN benign domains
│   │   ├── benign_messages.py      # 25 curated benign messages
│   │   └── robots_checker.py       # robots.txt compliance
│   ├── 📂 processors/             # 10-stage processing pipeline
│   │   ├── pipeline.py             # Pipeline orchestrator
│   │   ├── cleaner.py              # URL + text normalization
│   │   ├── labeler.py              # Label assignment
│   │   ├── evidence_scorer.py      # Evidence level A-E
│   │   ├── deduplicator.py         # URL hash deduplication
│   │   ├── conflict_detector.py    # Benign/malicious conflict
│   │   ├── pii_masker.py           # PII detection & masking
│   │   ├── named_entity_detector.py # Vietnamese name detection
│   │   ├── review_queue.py         # Review queue builder
│   │   ├── public_safety.py        # public_safe computation
│   │   └── training_ready.py       # training_ready computation
│   ├── 📂 exporters/              # Output generators
│   │   ├── private_raw.py          # JSONL raw exporter
│   │   ├── processed_private.py    # CSV/JSONL/Parquet private
│   │   ├── public_sanitizer.py     # Private → Public transform
│   │   ├── public_kaggle.py        # CSV/JSONL/Parquet public
│   │   ├── excel_metadata.py       # Excel metadata files
│   │   ├── readme_generator.py     # README.md for Kaggle
│   │   ├── dataset_card.py         # Kaggle Dataset Card
│   │   ├── license_notes.py        # LICENSE_NOTES.md
│   │   └── manifest.py             # data_manifest.json
│   ├── 📂 validators/             # Quality & compliance checks
│   │   ├── pii_validator.py        # PII absence verification
│   │   ├── redistribution_validator.py
│   │   ├── private_leak_check.py   # Private data leakage
│   │   ├── kaggle_gate.py          # 11-point publication gate
│   │   └── quality_report.py       # Markdown quality report
│   └── 📂 utils/                  # Shared utilities
│       └── http_client.py          # HTTP with retry + rate limit
│
├── 📂 data/                        # Output data (3 tầng)
│   ├── 📂 private_raw/            # ⛔ Raw data (KHÔNG public)
│   ├── 📂 processed_private/      # ⛔ Processed (KHÔNG public)
│   └── 📂 public_kaggle/          # ✅ Kaggle-ready (UPLOAD CÁI NÀY)
│
├── 📂 tests/                       # Test suite
│   ├── 📂 unit/                   # Unit tests
│   └── 📂 property/              # Property-based tests (Hypothesis)
│
└── 📂 reports/                     # Pipeline logs & quality reports
```

---

## 🔧 Cài đặt

### Yêu cầu
- Python 3.11+
- pip

### Quick Start

```bash
# 1. Clone
git clone https://github.com/Pak2k5/ScamShieldVN.git
cd ScamShieldVN

# 2. Cài dependencies
pip install -r requirements.txt

# 3. (Tùy chọn) Cấu hình API keys
copy .env.example .env
# Mở .env và điền API keys nếu có

# 4. Chạy pipeline
python -m src.main run
```

---

## 🚀 Sử dụng

### CLI Commands

```bash
# Xem help
python -m src.main --help

# Thu thập dữ liệu (tất cả nguồn)
python -m src.main collect

# Thu thập từ 1 nguồn cụ thể
python -m src.main collect --source urlhaus_malware

# Xử lý dữ liệu (10-stage pipeline)
python -m src.main process

# Xuất ra Kaggle format
python -m src.main export --target kaggle

# Kiểm tra chất lượng + Kaggle gate
python -m src.main validate

# Chạy toàn bộ end-to-end
python -m src.main run

# Debug mode
python -m src.main --verbose run
```

### Ví dụ thực tế

```bash
# Thu thập malware URLs từ URLhaus (miễn phí, CC0, ~10K URLs)
python -m src.main collect --source urlhaus_malware

# Thu thập top 1000 domains hợp lệ từ Tranco
python -m src.main collect --source tranco_top1000

# Xử lý toàn bộ dữ liệu đã thu thập
python -m src.main process

# Xuất và validate
python -m src.main export --target kaggle
python -m src.main validate
```

---

## ⚙️ Pipeline xử lý 10 bước

```
Raw JSONL → [1] Clean → [2] Label → [3] Evidence → [4] Dedup
    → [5] Conflict → [6] PII Mask → [7] NER → [8] Review Queue
    → [9] Public Safety → [10] Training Ready → Output
```

| Bước | Module | Chức năng |
|------|--------|-----------|
| 1 | `cleaner.py` | Chuẩn hóa URL (lowercase, remove port, sort params) + Unicode NFC |
| 2 | `labeler.py` | Gắn nhãn: phishing_url, malware_url, benign_url, scam_case... |
| 3 | `evidence_scorer.py` | Đánh giá evidence level A–E theo nguồn |
| 4 | `deduplicator.py` | Loại trùng lặp theo URL hash, giữ evidence cao nhất |
| 5 | `conflict_detector.py` | Phát hiện xung đột benign ↔ malicious |
| 6 | `pii_masker.py` | Mask: [PHONE_REDACTED], [EMAIL_REDACTED], [ID_REDACTED]... |
| 7 | `named_entity_detector.py` | Phát hiện tên người Việt (heuristic) |
| 8 | `review_queue.py` | Đưa record C/D/E, conflict, NER vào review queue |
| 9 | `public_safety.py` | Tính `public_safe` = an toàn để public |
| 10 | `training_ready.py` | Tính `training_ready` = đủ tin cậy để train AI |

---

## 📊 Nguồn dữ liệu

### Threat Feeds (Malicious URLs)

| Nguồn | Loại | License | Cần API Key |
|--------|------|---------|-------------|
| URLhaus (abuse.ch) | Malware URLs | CC0 ✅ | Không |
| PhishTank | Phishing URLs | Free research | Tùy chọn |
| OpenPhish | Phishing feed | Community | Không |
| Google Safe Browsing | URL verification | Google ToS | Có |
| VirusTotal | Detection stats | VT ToS | Có |

### Nguồn Việt Nam

| Nguồn | Loại | Phương pháp |
|--------|------|-------------|
| Cục ATTT / khonggianmang.vn | Taxonomy, cảnh báo | Seed URLs |
| Tín Nhiệm Mạng | Domain status | robots.txt check |
| Bộ Công an | Case patterns | Seed URLs |
| Ngân hàng Nhà nước | Banking warnings | Seed URLs |

### Benign References (Đối chứng)

| Nguồn | Số lượng | Loại |
|--------|----------|------|
| Vietnamese domains | 37 | Banking, e-wallet, e-commerce, logistics, telco, gov |
| Tranco List | 1,000 | Top international domains |
| Benign messages | 25 | OTP warning, delivery, bank education, promotion |

---

## 📐 Schema dữ liệu

### Labels (Nhãn chính)

| Label | Ý nghĩa |
|-------|---------|
| `phishing_url` | URL lừa đảo đã xác minh |
| `malware_url` | URL phát tán mã độc |
| `scam_case` | Case lừa đảo từ nguồn chính thức |
| `benign_url` | Domain/URL hợp lệ |
| `benign_message` | Tin nhắn không phải lừa đảo |
| `suspicious` | Đáng ngờ, chưa xác minh |
| `unknown` | Không đủ dữ liệu phân loại |

### Evidence Levels (Mức tin cậy)

| Level | Ý nghĩa | Training Ready? |
|-------|---------|-----------------|
| **A** | Threat feed chính thức + đã verify | ✅ Có |
| **B** | Nguồn uy tín cao hoặc 2+ nguồn xác nhận | ✅ Có |
| **C** | Community report có bằng chứng | ❌ Cần review |
| **D** | Nguồn tin cậy thấp | ❌ Không |
| **E** | Không xác minh được | ❌ Không |

### 18 loại lừa đảo (Vietnamese Scam Taxonomy)

| # | Loại | Tiếng Việt |
|---|------|-----------|
| 1 | impersonation_government | Giả mạo cơ quan nhà nước |
| 2 | impersonation_bank | Giả mạo ngân hàng |
| 3 | impersonation_logistics | Giả mạo đơn vị vận chuyển |
| 4 | impersonation_ecommerce | Giả mạo sàn TMĐT |
| 5 | fake_reward_gift | Trúng thưởng/quà tặng giả |
| 6 | fake_job_task | Việc làm giả/nhiệm vụ online |
| 7 | investment_crypto_forex | Đầu tư tiền ảo/forex giả |
| 8 | romance_scam | Lừa đảo tình cảm |
| 9 | fake_receipt | Biên lai chuyển tiền giả |
| 10 | sim_lock_standardization | Lừa chuẩn hóa thuê bao |
| 11 | social_account_takeover | Chiếm đoạt tài khoản MXH |
| 12 | recovery_scam | Lừa đảo lấy lại tiền |
| 13 | fake_app_remote_access | App giả/truy cập từ xa |
| 14 | qr_phishing | Lừa đảo mã QR |
| 15 | malware_distribution | Phát tán mã độc |
| 16 | gambling_lottery_scam | Cờ bạc/xổ số online |
| 17 | counterfeit_goods | Hàng giả/hàng nhái |
| 18 | other | Loại khác |

---

## 🔐 Kaggle Publication Gate

Trước khi publish, pipeline tự động chạy **11 kiểm tra**:

```
┌─────────────────────────────────────────────────────┐
│           KAGGLE PUBLICATION GATE (11/11)             │
├───┬────────────────────────────┬────────┬───────────┤
│ # │ Check                      │ Status │ Details   │
├───┼────────────────────────────┼────────┼───────────┤
│ 1 │ PII absence                │ ✅/❌  │           │
│ 2 │ License compliance         │ ✅/❌  │           │
│ 3 │ Redistribution compliance  │ ✅/❌  │           │
│ 4 │ Conflict records excluded  │ ✅/❌  │           │
│ 5 │ Private data excluded      │ ✅/❌  │           │
│ 6 │ Copyright excluded         │ ✅/❌  │           │
│ 7 │ Extractive summaries OK    │ ✅/❌  │           │
│ 8 │ Dataset card present       │ ✅/❌  │           │
│ 9 │ README present             │ ✅/❌  │           │
│10 │ Manifest present           │ ✅/❌  │           │
│11 │ Minimum records (≥100)     │ ✅/❌  │           │
└───┴────────────────────────────┴────────┴───────────┘
```

**Pipeline chặn publish nếu bất kỳ check nào FAIL.**

---

## 🔒 Bảo mật & Đạo đức

### Nguyên tắc bảo vệ dữ liệu

- ✅ **3 tầng dữ liệu**: private_raw → processed_private → public_kaggle
- ✅ **PII tự động mask**: SĐT, CCCD, email, STK, OTP, mật khẩu, số thẻ
- ✅ **robots.txt compliance**: Không crawl nếu nguồn cấm
- ✅ **Rate limiting**: Tối đa 1 req/s per domain
- ✅ **Redistribution policy**: URL từ nguồn cấm chỉ xuất derived features
- ✅ **.gitignore bảo vệ**: private_raw + processed_private không bao giờ commit

### Quy tắc sử dụng

| ✅ Được phép | ❌ Không được phép |
|-------------|-------------------|
| Nghiên cứu AI/ML | Buộc tội cá nhân |
| Phát triển tool phát hiện scam | Doxxing / quấy rối |
| Phân tích xu hướng lừa đảo | Public số điện thoại / STK |
| Giáo dục cộng đồng | Ra quyết định pháp lý tự động |

---

## 🤝 Đóng góp

Chúng tôi hoan nghênh mọi đóng góp! Xem [HUONG_PHAT_TRIEN.md](HUONG_PHAT_TRIEN.md) để biết roadmap.

### Cách đóng góp

1. Fork repository
2. Tạo branch: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "feat: add your feature"`
4. Push: `git push origin feature/your-feature`
5. Tạo Pull Request

### Cần đóng góp

- 🇻🇳 Thêm benign messages tiếng Việt
- 🏷️ Review records trong review queue
- 🔍 Cải thiện PII regex patterns
- 📝 Dịch tài liệu sang tiếng Anh
- 🧪 Thêm test cases

---

## 📄 License

- **Code pipeline**: MIT License
- **Dataset (curated portions)**: CC-BY-4.0
- **Third-party data**: Giữ nguyên license gốc (xem [LICENSE_NOTES.md](data/public_kaggle/LICENSE_NOTES.md))

---

## 📚 Citation

```bibtex
@dataset{scamshield_vn_2024,
  title={ScamShield VN: Vietnamese Online Scam & Phishing Detection Dataset},
  author={Phan Anh Khoa},
  year={2024},
  publisher={GitHub/Kaggle},
  url={https://github.com/Pak2k5/ScamShieldVN}
}
```

---

## 📬 Liên hệ

- **GitHub**: [Pak2k5](https://github.com/Pak2k5)
- **Issues**: [GitHub Issues](https://github.com/Pak2k5/ScamShieldVN/issues)

---

<p align="center">
  <b>Made with ❤️ for Vietnamese cybersecurity community</b>
</p>
