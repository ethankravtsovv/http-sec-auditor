# HTTP Security Header Auditor

Flask web app that scans any website's HTTP security headers and uses an AI model to grade them, triages phishing links/messages, and explains each security header. Built for academic cybersecurity labs.

Two versions ship in this repo — same audit logic, different AI backend:

| File | AI Backend | Default Model | API Key Env Var | Extra Dep | Tabs |
|------|-----------|---------------|-----------------|-----------|------|
| `app.py` | Google Gemini | `gemini-2.5-flash` | `GEMINI_API_KEY` | `google-genai` | Header audit only |
| `app_claude.py` | Anthropic Claude | `claude-haiku-4-5` | `ANTHROPIC_API_KEY` | `anthropic` | Audit + Phishing Triage + Header Reference |

## Running It

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt

# Claude version (recommended):
export ANTHROPIC_API_KEY=your-key        # from console.anthropic.com
.venv/bin/python app_claude.py           # → http://localhost:5000

# Gemini version:
export GEMINI_API_KEY=your-key           # from aistudio.google.com
.venv/bin/python app.py                  # → http://localhost:5000
```

Without an API key the header audit still works — you get the headers table, just no AI grade. The phishing tab needs the key.

**Docker** (gunicorn, Claude version by default):

```sh
docker build -t http-sec-auditor .
docker run -p 8000:8000 -e ANTHROPIC_API_KEY=your-key http-sec-auditor
# Gemini instead: -e APP_MODULE=app:app -e GEMINI_API_KEY=your-key
```

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | — | AI backend credential |
| `CLAUDE_MODEL` / `GEMINI_MODEL` | `claude-haiku-4-5` / `gemini-2.5-flash` | Model override |
| `PORT` | `5000` | Dev-server port |
| `RATE_LIMIT_PER_MINUTE` | `10` | Per-IP limit on `/scan` and `/phishing` |
| `ALLOW_PRIVATE_TARGETS` | off | Set `1` to allow scanning private/loopback IPs (lab use) |

## The Three Tabs (Claude version)

### 1. Header_Audit (`/`)

Enter a domain → the app fetches it (10s timeout, browser User-Agent, redirects followed hop-by-hop), checks six security headers on the final response, and asks the AI for a letter grade (A–F), a verdict, and per-header findings with copy-pasteable fixes.

```
POST /scan → normalize_url() → safe_fetch() → audit_headers() → claude_grade() → render
```

### 2. Phishing_Triage (`/phishing`)

Paste a suspicious link, SMS, or email text. Analysis is **fully passive — the link is never opened, fetched, or resolved** (visiting it could tip off the attacker or fire a tracking token). URLs are regex-extracted and judged as text.

Claude returns a risk level (LOW / MEDIUM / HIGH), a verdict, indicator cards (lookalike domains, punycode/IP hosts, urgency tactics, credential-harvesting language…), and a recommended action.

### 3. Header_Reference (`/headers`)

Static explainer cards for the six audited headers — what each does, the attack it blocks, a safe starting value to copy, and a practical deployment note. No API call.

## The Six Audited Headers

- `Content-Security-Policy` — restricts what the browser can load (XSS defense)
- `Strict-Transport-Security` — forces HTTPS for future visits
- `X-Frame-Options` — blocks iframe embedding (clickjacking defense)
- `X-Content-Type-Options` — prevents MIME-type sniffing
- `Referrer-Policy` — controls referrer info sent to other sites
- `Permissions-Policy` — restricts browser features (camera, mic, etc.)

The app also sends these headers on its own responses (minus HSTS, which belongs on the TLS-terminating proxy), with a `'self'`-only CSP — all assets are compiled and served same-origin, no CDNs.

## Hardening

- **SSRF guard** — targets resolving to private, loopback, link-local, or metadata addresses are refused, and every redirect hop is re-checked. `ALLOW_PRIVATE_TARGETS=1` disables this for lab scans of your own gear. The DNS check and the fetch are separate lookups, so treat it as a guardrail, not a boundary — don't run this reachable from untrusted networks.
- **Rate limiting** — per-IP sliding window on the two endpoints that spend API credit.
- **Headers only** — response bodies are never downloaded, and only the first 8 kB of pasted phishing text is sent to the AI.

## AI Integration Details

Both AI functions send a plain-text summary and expect JSON back, and both fail soft: any API error (bad key, rate limit, timeout, invalid JSON) logs a warning and the page renders without AI output. The app never crashes on AI failure.

**Claude (`claude_grade()` / `claude_phish_check()`):**
- `anthropic` SDK, `client.messages.create()` with a system prompt
- Claude may wrap JSON in prose or a code fence, so the response is sliced from the first `{` to the last `}` before parsing
- 30s client timeout so a stalled call degrades gracefully
- `claude-haiku-4-5` is fast (~2–5s) and cheap. Swap in `claude-sonnet-5` or `claude-opus-4-8` via `CLAUDE_MODEL` for deeper analysis at higher latency/cost.

**Gemini (`gemini_grade()`):**
- `google-genai` SDK with `response_mime_type="application/json"` to force raw JSON
- If the default model is unavailable on your tier, override `GEMINI_MODEL` (check aistudio.google.com/apikey)

## Routes & Functions (Claude version)

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Header audit form |
| `/scan` | POST | Run the header audit |
| `/phishing` | GET/POST | Phishing triage form / analysis |
| `/headers` | GET | Static header reference |

| Function | Purpose |
|----------|---------|
| `normalize_url(raw)` | Prepend `https://`, validate scheme, or raise `ValueError` |
| `resolve_target_ip(host)` | Resolve and refuse non-public addresses (SSRF guard) |
| `safe_fetch(url)` | GET with per-hop redirect validation, headers only |
| `rate_limited(ip)` | Per-IP sliding-window limiter |
| `audit_headers(headers)` | Check the six headers, return presence + raw values |
| `claude_grade(host, rows)` | Grade the audit → `{grade, verdict, findings}` or `None` |
| `claude_phish_check(text)` | Triage pasted text → `{risk, verdict, indicators, advice}` or `None` |
| `run_scan(url)` | Orchestrate: fetch → audit → grade → template context |
| `grade_theme()` / `risk_theme()` | Map grades/risk to green/yellow/red Tailwind classes |

The template is split into shared chunks (`PAGE_TOP` with the nav tabs, `PAGE_BOTTOM` with the footer) plus one body per tab, concatenated into `TEMPLATE`, `PHISHING_TEMPLATE`, and `REFERENCE_TEMPLATE`.

## Frontend Assets

Everything in `static/` is self-hosted: compiled Tailwind, fonts (Inter + JetBrains Mono, latin subset), and the copy-button script. After changing template markup, rebuild the CSS:

```sh
npx tailwindcss@3.4.17 -i tailwind.input.css -o static/tailwind.css --minify
```

## Error Handling

| Failure | Behavior |
|---------|----------|
| Invalid URL / bad scheme / empty input | Error banner, stay on form |
| Private/non-public target | Error banner (SSRF guard) |
| Target unreachable / timeout / redirect loop | Error banner |
| Rate limit hit | Error banner, HTTP 429 |
| AI API failure | Audit: headers table renders without grade. Phishing: error banner. |

## Notes

- A missing header isn't automatically a vulnerability: large sites (e.g. google.com) often mitigate the same risks through other mechanisms like report-only CSP and sandbox domains. Interpret grades in context.
- An A grade requires all six headers present with strong values — rare in the wild. securityheaders.com sends all six if you want to see one.

## License

MIT
