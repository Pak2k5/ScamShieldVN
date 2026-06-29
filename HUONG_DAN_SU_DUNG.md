# 📖 Hướng Dẫn Sử Dụng ScamShield VN

## Giới thiệu

ScamShield VN là một pipeline Python CLI thu thập, xử lý và xuất bộ dữ liệu phát hiện lừa đảo trực tuyến tại Việt Nam. Pipeline tự động hóa toàn bộ quy trình từ thu thập dữ liệu thô đến xuất dataset an toàn sẵn sàng upload Kaggle.

---

## Yêu cầu hệ thống

- Python >= 3.11
- Windows / Linux / macOS
- Kết nối internet (để thu thập dữ liệu từ threat feeds)
- Dung lượng ổ đĩa: ~500MB cho dataset đầy đủ

---

## Cài đặt

### Bước 1: Clone repository

```bash
git clone https://github.com/Pak2k5/ScamShieldVN.git
cd ScamShieldVN
```

### Bước 2: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

### Bước 3: Cấu hình API keys (tùy chọn)

Copy file mẫu và điền API keys nếu có:

```bash
copy .env.example .env
```

Mở file `.env` và điền:
```
SCAMSHIELD_PHISHTANK_KEY=your_phishtank_key
SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY=your_gsb_key
SCAMSHIELD_VIRUSTOTAL_KEY=your_vt_key
```

> **Lưu ý**: Pipeline vẫn chạy được mà không cần API key. Các nguồn miễn phí (URLhaus, OpenPhish, Tranco, benign domains/messages) không yêu cầu key.

---

## Sử dụng cơ bản

### Lệnh chính

```bash
python -m src.main <subcommand> [options]
```

### Các subcommand

| Lệnh | Chức năng |
|------|-----------|
| `collect` | Thu thập dữ liệu từ các nguồn |
| `process` | Xử lý dữ liệu (10 bước pipeline) |
| `export` | Xuất ra CSV/JSONL/Parquet/Excel |
| `validate` | Kiểm tra chất lượng + Kaggle gate |
| `run` | Chạy toàn bộ pipeline (collect → process → export → validate) |

### Options toàn cục

| Flag | Mặc định | Mô tả |
|------|----------|-------|
| `--config PATH` | `config/sources.yaml` | Đường dẫn file cấu hình nguồn |
| `--output-dir PATH` | `./data` | Thư mục output |
| `--verbose` | OFF | Bật chế độ debug logging |

---

## Hướng dẫn chi tiết từng bước

### 📥 Bước 1: Thu thập dữ liệu (Collect)

**Thu thập từ tất cả nguồn:**
```bash
python -m src.main collect
```

**Thu thập từ 1 nguồn cụ thể:**
```bash
python -m src.main collect --source urlhaus_malware
python -m src.main collect --source benign_domains_vn
python -m src.main collect --source benign_messages
python -m src.main collect --source tranco_top1000
python -m src.main collect --source openphish_feed
```

**Kết quả:** File JSONL xuất hiện trong `data/private_raw/`

**Nguồn không cần API key:**
- `urlhaus_malware` — ~10,000+ malware URLs (CC0 license)
- `openphish_feed` — Phishing URLs (public feed)
- `tranco_top1000` — Top 1000 domains quốc tế (benign)
- `benign_domains_vn` — 37 domains Việt Nam hợp lệ
- `benign_messages` — 25 tin nhắn mẫu tiếng Việt

**Nguồn cần API key:**
- `phishtank_verified` — Cần `SCAMSHIELD_PHISHTANK_KEY`
- `google_safe_browsing` — Cần `SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY`
- `virustotal` — Cần `SCAMSHIELD_VIRUSTOTAL_KEY`

---

### ⚙️ Bước 2: Xử lý dữ liệu (Process)

```bash
python -m src.main process
```

Pipeline 10 bước tự động chạy:

1. **Clean** — Chuẩn hóa URL (lowercase, remove port, sort params) + Unicode NFC
2. **Label** — Gắn nhãn: phishing_url, malware_url, benign_url, scam_case...
3. **Evidence Score** — Đánh giá mức độ tin cậy A/B/C/D/E
4. **Deduplicate** — Loại bỏ trùng lặp theo URL hash
5. **Conflict Detect** — Phát hiện xung đột benign vs malicious
6. **PII Mask** — Ẩn thông tin cá nhân (SĐT, CCCD, email, STK...)
7. **Named Entity** — Phát hiện tên người trong text tiếng Việt
8. **Review Queue** — Đưa record không chắc chắn vào hàng chờ review
9. **Public Safety** — Tính toán record nào an toàn để public
10. **Training Ready** — Xác định record nào đủ tin cậy để train AI

**Kết quả:** File xuất hiện trong `data/processed_private/`
- `scamshield_vn_processed.jsonl` — Dataset đã xử lý
- `review_queue.csv` — Danh sách cần human review

---

### 📤 Bước 3: Xuất dữ liệu (Export)

**Xuất cho Kaggle:**
```bash
python -m src.main export --target kaggle
```

**Xuất tất cả (private + public):**
```bash
python -m src.main export
```

**Kết quả trong `data/public_kaggle/`:**

| File | Mô tả |
|------|--------|
| `scamshield_vn_public.csv` | Dataset chính (CSV) |
| `scamshield_vn_public.jsonl` | Dataset chính (JSONL) |
| `scamshield_vn_public.parquet` | Dataset chính (Parquet - nhanh nhất) |
| `source_registry.xlsx` | Danh sách nguồn dữ liệu |
| `scam_taxonomy.xlsx` | 18 loại lừa đảo tiếng Việt |
| `sample_records.xlsx` | Mẫu 1000 records |
| `review_queue_summary.xlsx` | Tổng hợp review queue |
| `README.md` | Mô tả dataset |
| `dataset_card.md` | Kaggle Dataset Card |
| `LICENSE_NOTES.md` | Thông tin bản quyền từng nguồn |
| `data_manifest.json` | Version, checksums, metadata |

---

### ✅ Bước 4: Kiểm tra trước khi publish (Validate)

```bash
python -m src.main validate
```

Chạy 11 kiểm tra tự động:

| # | Kiểm tra | Ý nghĩa |
|---|----------|---------|
| 1 | PII absence | Không có thông tin cá nhân thô |
| 2 | License compliance | Có file LICENSE_NOTES.md |
| 3 | Redistribution compliance | URL từ nguồn cấm đã bị redact |
| 4 | Conflict excluded | Record xung đột đã bị loại |
| 5 | Private data excluded | Không có dữ liệu private |
| 6 | Copyright excluded | Không có bài báo nguyên văn |
| 7 | Extractive reviewed | Summary trích xuất đã review |
| 8 | Dataset card present | Có dataset_card.md |
| 9 | README present | Có README.md |
| 10 | Manifest present | Có data_manifest.json |
| 11 | Minimum records | ≥100 records training-ready |

**Nếu PASS tất cả** → Sẵn sàng upload Kaggle!  
**Nếu FAIL** → Xem chi tiết lỗi và sửa trước khi upload.

---

### 🚀 Chạy toàn bộ pipeline 1 lần

```bash
python -m src.main run
```

Tương đương: collect → process → export → validate.

---

## Upload lên Kaggle

Sau khi validate PASS, upload folder `data/public_kaggle/` lên Kaggle:

```bash
# Cài kaggle CLI
pip install kaggle

# Upload dataset
kaggle datasets create -p data/public_kaggle/
```

Hoặc upload thủ công qua giao diện web Kaggle.

---

## Cấu trúc thư mục dữ liệu

```
data/
├── private_raw/          ← Dữ liệu thô (KHÔNG commit, KHÔNG upload)
│   ├── urlhaus_malware_20240115.jsonl
│   ├── benign_domains_vn_20240115.jsonl
│   └── PRIVATE_DATA_WARNING.md
├── processed_private/    ← Đã xử lý (KHÔNG commit)
│   ├── scamshield_vn_processed.jsonl
│   ├── scamshield_vn_processed.csv
│   ├── scamshield_vn_processed.parquet
│   └── review_queue.csv
└── public_kaggle/        ← AN TOÀN để public ← UPLOAD CÁI NÀY
    ├── scamshield_vn_public.csv
    ├── scamshield_vn_public.jsonl
    ├── scamshield_vn_public.parquet
    └── ...
```

---

## Troubleshooting

### Lỗi "No module named 'httpx'"
```bash
pip install httpx tenacity loguru pydantic python-dotenv pyyaml pandas pyarrow openpyxl
```

### Lỗi "No processed data found"
Chạy `collect` và `process` trước khi `export`:
```bash
python -m src.main collect
python -m src.main process
```

### Kaggle gate FAIL ở "minimum_records"
Cần thu thập thêm dữ liệu. Chạy:
```bash
python -m src.main collect --source urlhaus_malware
python -m src.main collect --source tranco_top1000
```

### Muốn xem log chi tiết
```bash
python -m src.main --verbose run
```
Log file tự động lưu trong `reports/pipeline_YYYYMMDD_HHMMSS.log`

---

## Lưu ý quan trọng

⚠️ **KHÔNG bao giờ upload `data/private_raw/` hoặc `data/processed_private/` lên bất kỳ đâu.**

⚠️ **KHÔNG commit file `.env` chứa API key lên GitHub.**

⚠️ **Dataset chỉ dùng cho nghiên cứu. KHÔNG dùng để buộc tội cá nhân hoặc ra quyết định pháp lý.**
