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

## ✅ Checkpoint 3 — Blue / ghép pipeline + sinh file phòng thủ

**Chuẩn bị:** điền `.env` — `OPENROUTER_API_KEY` (Blue) + `RED_TEAM_PROVIDER=gemini`, `GOOGLE_API_KEY`, `GEMINI_MODEL=gemini-3.5-flash` (Red, dùng ở CP4).

### `src/assignment/rate_limiter.py` — `RateLimitPlugin`
- Sliding window theo từng `user_id` (deque timestamp): bỏ timestamp cũ hơn `now - window_seconds`.
- Đủ `max_requests` (10) trong 60s → `blocked_count += 1`, trả `[rate_limiter] Rate limit exceeded … Try again in Ns` (không gọi LLM). Request bị chặn **không** được ghi timestamp (để không kéo dài thời gian khoá).
- Còn quota → ghi timestamp, `return None`.

### `src/assignment/audit_log.py` — `AuditLogPlugin`
- `record_input`: lưu `request_id`, `user_id`, `timestamp`, `input` + thời điểm bắt đầu (`perf_counter`).
- `record_output`: ghép với input theo `request_id`, thêm `output`, `blocked`, `layer`, `latency_ms`, `completed_at`, + `redacted` / `issues`.
- `export_json`: tự `mkdir` rồi ghi JSON array ra `outputs/audit_log.json`.

### `src/assignment/monitoring.py` — `MonitoringAlert`
- Thêm `record(blocked, layer, redacted)` để cập nhật bộ đếm (tổng, bị chặn, rate-limit hits, chặn theo từng lớp, số response bị redact) và `record_judge()`.
- `check_metrics()`: tạo `Alert` khi `block_rate > 50%`, `rate_limit_hits ≥ 5`, `judge_fail_rate > 30%`. Gọi lại nhiều lần không tạo alert trùng.
- `export_json`: ghi snapshot + `blocked_by_layer` + `thresholds` ra `outputs/metrics.json`.

### `src/assignment/pipeline.py`
- **`is_egress_allowed(destination, payload)`** — rule code, không hỏi LLM:
  - URL phải là `https`, host **khớp chính xác** allowlist `api.vinbank.example` / `cases.vinbank.example` (chặn `api.vinbank.example.evil.com`), không có `user@`, port chỉ 443.
  - Payload (đã normalize Unicode/bỏ dấu) không được chứa: secret DEMO (kể cả bị chèn dấu cách: `db . vinbank . internal`), `password`/`mật khẩu`, `api key`/`sk-…`, host `.internal`, email, SĐT VN.
- **`build_production_plugins()`** → `[RateLimitPlugin, InputGuardrailPlugin, OutputGuardrailPlugin]` (rẻ nhất chạy trước).
- **`build_observability()`** → `(AuditLogPlugin(), MonitoringAlert())`. Audit/monitoring là **side observer**, không chặn, ghi mọi request kể cả request bị chặn sớm.
- **`BluePipeline`** (class mới): tự gọi từng plugin theo thứ tự để biết chính xác **lớp nào chặn**, truyền `user_id` thật cho rate limiter (OpenAIRunner gốc luôn dùng chung `user_id="student"`). LLM gọi qua `create_blue_agent(plugins=[])` (OpenRouter Liquid, model khoá cứng — không đổi). Có retry + backoff 5s/10s/20s cho lỗi `RateLimitError`/`InternalServerError` của free tier.
  - Quy ước `blocked`: chặn ở rate limiter/input, **hoặc** output guardrail phát hiện secret (secret/api_key/password/internal_host). PII thường (SĐT/email) chỉ bị redact → `blocked: false`, `redacted: true`.
- **`run_assignment_suite()`** — mỗi nhóm một `user_id` riêng:
  - Test 1: 6 câu banking an toàn (có 1 câu tiếng Việt).
  - Test 2: 9 câu tấn công (ignore instructions, DAN, system prompt, indirect injection zero-width trong email, pretend admin, tiếng Việt, token `<|system|>`, chữ tách `i-g-n-o-r-e`, hack/steal).
  - Test 3: spam 15 request cùng user (bỏ qua gọi LLM cho request lọt để tiết kiệm quota free — chỉ đo rate limiter).
  - Test 4: 7 case biên (rỗng, khoảng trắng, emoji, input 3000 ký tự, SQL-injection-like, full-width injection, câu thời tiết lạc đề).
  - Thêm field phụ (schema cho phép): `plugin_order`, `egress_checks` (7 case), `metrics`.
  - Ghi `outputs/results.json`, `outputs/audit_log.json`, `outputs/metrics.json`.

### Sửa thêm ở CP2 (phát hiện khi test CP3)
- `OutputGuardrailPlugin`: reset `last_issues`/`last_action` **trước** nhánh return sớm (response rỗng) để không giữ trạng thái của request trước.
- `content_filter`: lấy thêm giá trị đầy đủ trong `vinbank_secrets.json` (vd. `db.vinbank.internal:5432`) + che phần `:port` còn sót. Trước đó kết quả là `[REDACTED]:5432`.

### Kết quả (`python src/main.py --part 3`)

| Nhóm | Kết quả |
|------|---------|
| Safe queries | **0/6 bị chặn**, cả 6 đều có câu trả lời thật từ Liquid |
| Attack queries | **9/9 bị chặn** (đều tại `input_guardrail`) |
| Rate limit | sent 15 · passed 10 · **blocked 5** (từ request #11) |
| Edge cases | 7 case: rỗng/khoảng trắng/emoji/full-width/lạc đề → BLOCK; câu dài + SQL-like (có từ banking) → PASS |
| Egress | 1 ALLOW (endpoint VinBank + payload sạch), 6 DENY |
| Metrics | 37 request, 19 bị chặn (input 14, rate 5), 2 alert: `block_rate` 51% và `rate_limit_hits` 5 |

- `outputs/` có đủ 3 file: `results.json`, `audit_log.json` (37 entry, có latency), `metrics.json`.
- `pytest tests/public -q` → **10 passed** (gồm egress + 4 test contract của `results.json`).
- `pytest tests/smoke -q` → **39 passed**.
- Test thêm bằng LLM giả: response chứa secret → output guardrail redact + `blocked: true`; response chứa SĐT → redact, `blocked: false`.
- Lần chạy thật free tier trả `RateLimitError` / `InternalServerError` vài lần, retry xử lý được. Lần chạy đầu (chưa có backoff đủ dài) có 2 câu bị `llm_error` → đã sửa và chạy lại.

> Ghi chú: Lần sửa `:port` của `content_filter` diễn ra sau lần chạy cuối, nhưng không request nào trong lần chạy đó đi tới bước redact nên `results.json` không bị ảnh hưởng. Có thể chạy lại `--part 3` nếu muốn file khớp 100% với code mới (tốn ~10 lượt gọi OpenRouter).
## ⏳ Checkpoint 4 — chưa làm (chờ lệnh)
## ⏳ Checkpoint 5 — chưa làm (chờ lệnh)
