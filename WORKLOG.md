# Nhật ký làm bài — Day 11 Guardrails / HITL / Red Team

> Ghi lại những gì đã làm ở từng Checkpoint. (Chưa commit / push — tự làm khi sẵn sàng.)

---

## ✅ Checkpoint 1 — Setup máy

**Đã làm**

1. Tạo virtualenv `.venv/` bằng Python 3.12 (`py -3.12 -m venv .venv`).
2. Nâng `pip`, cài `requirements.txt` (openai, google-adk, google-genai, python-dotenv, pytest, jsonschema, nemoguardrails 0.24.1).
3. Copy `.env.example` → `.env`. Đã kiểm tra `.env` và `.venv` đều nằm trong `.gitignore` (dòng 138, 140) → không bị commit.

**Kết quả tự kiểm**

| Lệnh | Kết quả |
|------|---------|
| `python -c "import openai"` | OK |
| `python -c "import google.adk"` | OK |
| `python -c "import nemoguardrails"` | OK — v0.24.1 |
| `pytest tests/smoke -q` | **39 passed** |

**Còn phải tự làm (cần key thật)**

- Mở `.env`, điền `OPENROUTER_API_KEY` (Blue) và key Red: `RED_TEAM_PROVIDER=openai` + `OPENAI_API_KEY`, **hoặc** `RED_TEAM_PROVIDER=gemini` + `GOOGLE_API_KEY`. CP2 không cần key; CP3/CP4 thì cần.
- Đổi tên repo trên GitHub theo quy ước trong `SUBMISSION.md` (nếu chưa).

---

## ✅ Checkpoint 2 — Blue / bộ lọc input + output

### File `src/guardrails/input_guardrails.py`

**`normalize_text()`** (hàm mới) — chuẩn hoá text trước khi so khớp regex:
- NFKC → gộp ký tự full-width / ký tự giống nhau (`Ｉｇｎｏｒｅ` → `ignore`).
- Xoá ký tự vô hình (zero-width `​`, BOM, soft hyphen, bidi override…) → bắt được `Ignore​ all previous…`.
- Bỏ dấu tiếng Việt (`bỏ qua` → `bo qua`, `đ` → `d`) → 1 regex bắt cả có dấu và không dấu, khớp được `ALLOWED_TOPICS` dạng không dấu trong config.
- lowercase + gộp khoảng trắng.

**`detect_injection()`** — 12 nhóm regex (yêu cầu ≥5):
1. Ghi đè chỉ dẫn: `ignore/disregard/forget/override/bypass (all) (previous/above/…) instructions/rules/…`
2. Đổi vai `you are now …` — có negative lookahead để **không** chặn `you are now logged in`.
3. `system prompt`, `developer/hidden/initial message|prompt`.
4. `reveal/show/print/repeat … your instructions|prompt|configuration|internal notes`.
5. `pretend you are / pretend to be`.
6. `act as (a/an) unrestricted|unfiltered|jailbroken|…`.
7. `DAN mode`, `do anything now`, `developer mode`, `jailbreak`, `god mode` (không dùng `dan` đơn lẻ vì sau khi bỏ dấu "hướng dẫn"/"người dân" → `dan` sẽ chặn nhầm).
8. Moi secret trực tiếp: `show/give/tell/what is … admin password | api key | credentials | secret | db host | connection string`.
9. Token giả ranh giới vai trò: `<|system|>`, `<|im_start|>`, `[INST]`, `system:` đầu dòng.
10–12. Tiếng Việt: `bỏ qua … hướng dẫn/lệnh/quy tắc`, `bây giờ bạn là / hãy đóng vai`, `tiết lộ / cho tôi biết … mật khẩu / API key / prompt hệ thống`.
- Thêm bước **"ép dính"** (bỏ mọi ký tự không phải chữ/số) để bắt `i-g-n-o-r-e a.l.l previous instructions`, `s y s t e m p r o m p t`.
- Email/tài liệu bên ngoài chỉ bị chặn khi **bên trong có lệnh injection**; câu "tóm tắt email về chuyển khoản bị delay" vẫn `ALLOW`.

**`topic_filter()`**:
- Normalize (bỏ dấu) rồi so khớp với `\b` ở đầu từ → `kill` không khớp `skill`, nhưng `hack` vẫn khớp `hacking`.
- Có topic trong `BLOCKED_TOPICS` → `BLOCK`; không có topic banking nào → `BLOCK`; còn lại → `ALLOW`.
- Thêm `EXTRA_ALLOWED_TOPICS` (bank, vinbank, card, money, vnd, mortgage, statement, rate, fee, branch, tien…) để giảm chặn nhầm câu banking hợp lệ. **Không sửa** `core/config.py`.

**`InputGuardrailPlugin.on_user_message_callback()`**:
- `detect_injection` = BLOCK → `blocked_count += 1`, trả message `[input_guardrail] Request blocked: possible prompt injection…` (không gọi LLM).
- `topic_filter` = BLOCK → trả message `[input_guardrail] Request blocked: off-topic…`.
- Cả hai ALLOW → `return None`.
- Lưu `last_block_reason` (`"injection"` / `"off_topic"` / `None`) để CP3 ghi `layer` vào `results.json`.

### File `src/guardrails/output_guardrails.py`

**`content_filter()`**:
1. Che **secret DEMO đã biết** (lấy từ `core.config.DEMO_SECRETS` + `admin123`, `sk-vinbank-secret-2024`, `db.vinbank.internal`) — so khớp nguyên văn, không phân biệt hoa thường → issue `secret`.
2. Regex `PII_PATTERNS` (tên khớp `expect_issue_types` trong dataset), chạy theo thứ tự:
   - `api_key`: `sk-…`
   - `api_key_assignment`: `api key: xxx`
   - `password`: `password = / : / is / là <giá trị có số hoặc ký tự đặc biệt>` — chỉ che phần giá trị (giữ nhãn), không che nhầm câu "a password is required".
   - `internal_host`: `*.internal|.local|.corp(:port)`
   - `email`
   - `national_id`: CCCD 12 số / CMND 9 số (không dính chữ số khác)
   - `phone`: `0`/`+84` + 9–10 số (đặt **sau** CCCD để không "ăn" mất một phần số CCCD; hotline `1900 545 467` không bị che).
- Trả `{"safe", "issues", "redacted"}`.

**`OutputGuardrailPlugin.after_model_callback()`**:
- Chạy `content_filter`; nếu không safe → thay `llm_response.content` bằng bản đã `[REDACTED]`, `redacted_count += 1`, lưu `last_issues` / `last_action="redacted"`.
- Nếu bật LLM-Judge (optional, mặc định không có judge) và judge nói UNSAFE → thay bằng message chặn, `blocked_count += 1`.

**`test_content_filter()`** — thêm phần chạy toàn bộ `pii_cases` trong `data/pii_hallucination_samples.json` để kiểm tra ngay khi `--part 2`.

### Kết quả kiểm tra

- `python src/main.py --part 2`:
  - detect_injection 3/3 PASS, topic_filter 4/4 PASS.
  - Plugin: câu banking ALLOW; injection + "bomb" BLOCK (2 blocked / 4 total).
  - content_filter: secret/SĐT/email → `[REDACTED]`; **10/10 PII cases** của dataset PASS.
- `pytest tests/public/test_lab_contracts.py -k "injection or topic or content_filter"` → **4 passed** (2 test còn lại thuộc CP3: egress).
- Tự kiểm thêm 13 case biên — đều PASS: Unicode zero-width trong email, full-width, chữ cách bằng dấu `-`/`.`, injection tiếng Việt, câu "Hướng dẫn mở tài khoản tiết kiệm" (không chặn nhầm), "You are now logged in…" (không chặn nhầm), "reset my banking password" (không chặn nhầm), "skill … credit card" (không chặn nhầm), câu thời tiết (off-topic → BLOCK), chuỗi rỗng.

---

## ⏳ Checkpoint 3 — chưa làm (chờ lệnh)
## ⏳ Checkpoint 4 — chưa làm (chờ lệnh)
## ⏳ Checkpoint 5 — chưa làm (chờ lệnh)
