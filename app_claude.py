"""HTTP Security Header Auditor — academic security lab console.

Run:  ANTHROPIC_API_KEY=... python app_claude.py   →   http://localhost:5000
Deps: pip install flask requests anthropic
"""

import ipaddress
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, render_template_string, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # form posts only; keep them small

# Behind a reverse proxy every request arrives from the proxy's IP, which
# would put all visitors in one rate-limit bucket. Set TRUSTED_PROXY_HOPS to
# the number of proxies in front (usually 1) to take the client IP from
# X-Forwarded-For instead. Leave unset when directly exposed — a spoofable
# XFF header must never be trusted without a proxy that overwrites it.
_proxy_hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
if _proxy_hops:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_proxy_hops, x_proto=_proxy_hops)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5")

MAX_REDIRECTS = 5
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "10"))
CLAUDE_SYSTEM_INSTRUCTION = (
    "You are a web security auditor. Given this list of present and missing "
    "HTTP security headers for a site, return: (1) a single letter grade A-F, "
    "(2) a one-sentence overall verdict, (3) for each missing or "
    "weakly-configured header, the concrete risk and the exact header line "
    "the site should add. Respond in JSON: "
    '{grade, verdict, findings:[{header, status, risk, fix}]}.'
)

# Static content for the Header_Reference tab.
HEADER_REFERENCE = [
    {
        "name": "Content-Security-Policy",
        "defends": "XSS",
        "what": "Whitelists where the browser may load scripts, styles, images, and frames from. The single most powerful header — and the hardest to get right.",
        "attack": "Cross-site scripting (XSS): injected JavaScript runs with full access to the page, stealing sessions and form input.",
        "example": "Content-Security-Policy: default-src 'self'",
        "note": "Deploy as Content-Security-Policy-Report-Only first — a strict CSP will break inline scripts until you clean them up.",
    },
    {
        "name": "Strict-Transport-Security",
        "defends": "MITM",
        "what": "Tells the browser to only ever connect over HTTPS for the given duration, even if the user types http:// or clicks an http link.",
        "attack": "SSL-stripping man-in-the-middle: an attacker on the network downgrades the connection to plaintext HTTP and reads everything.",
        "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "note": "Only add 'preload' once you are certain — removal from the browser preload list takes months.",
    },
    {
        "name": "X-Frame-Options",
        "defends": "Clickjacking",
        "what": "Controls whether the page may be embedded in an <iframe> on another site.",
        "attack": "Clickjacking: your page is loaded invisibly over a decoy so the victim clicks your buttons without knowing.",
        "example": "X-Frame-Options: SAMEORIGIN",
        "note": "The modern replacement is CSP's frame-ancestors directive; sending both is fine.",
    },
    {
        "name": "X-Content-Type-Options",
        "defends": "MIME sniffing",
        "what": "Forbids the browser from guessing (sniffing) a response's content type and overriding the declared one.",
        "attack": "A user-uploaded 'image' that is actually HTML/JS gets sniffed and executed as a script in your origin.",
        "example": "X-Content-Type-Options: nosniff",
        "note": "One fixed value, zero breakage risk — there is no excuse to omit this one.",
    },
    {
        "name": "Referrer-Policy",
        "defends": "Data leakage",
        "what": "Controls how much of the current URL is sent in the Referer header when the user navigates to another site.",
        "attack": "Full URLs containing tokens, search queries, or private paths leak to every third-party site you link to.",
        "example": "Referrer-Policy: strict-origin-when-cross-origin",
        "note": "Modern browsers default to this value; set it explicitly to cover older ones or to go stricter (no-referrer).",
    },
    {
        "name": "Permissions-Policy",
        "defends": "Feature abuse",
        "what": "Opt-out switchboard for powerful browser features — camera, microphone, geolocation, USB — for your page and embedded iframes.",
        "attack": "A compromised third-party script or rogue iframe silently requests camera/location access under your origin.",
        "example": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "note": "List only features you never use; an empty allowlist () disables the feature entirely.",
    },
]

URL_RE = re.compile(r"""https?://[^\s<>"']+|www\.[^\s<>"']+""", re.IGNORECASE)

PHISH_SYSTEM_INSTRUCTION = (
    "You are a phishing triage analyst in an academic security lab. The user "
    "pastes a suspicious URL, SMS, or email text. Judge it from the text alone "
    "— the link is never visited. Look for lookalike/typosquatted domains, "
    "deceptive subdomains, IP-literal or punycode hosts, URL shorteners, "
    "mismatched display text vs actual target, credential-harvesting language, "
    "and urgency/pressure tactics. Legitimate messages exist too — do not "
    "invent indicators that are not there. Respond in JSON: "
    '{risk: "low"|"medium"|"high", verdict: <one sentence>, '
    'indicators: [{title, severity: "info"|"warning"|"critical", detail}], '
    'advice: <2-3 sentences telling the user what to do>}.'
)

# Tailwind color classes per grade band (full class names so the Tailwind
# build picks them up when scanning this file).
GRADE_THEMES = {
    "green": {
        "text": "text-emerald-500",
        "border": "border-emerald-500",
        "ring_glow": "shadow-[0_0_30px_rgba(16,185,129,0.2)]",
        "card_glow": "shadow-[0_0_30px_rgba(16,185,129,0.1)]",
    },
    "yellow": {
        "text": "text-yellow-500",
        "border": "border-yellow-500",
        "ring_glow": "shadow-[0_0_30px_rgba(234,179,8,0.2)]",
        "card_glow": "shadow-[0_0_30px_rgba(234,179,8,0.1)]",
    },
    "red": {
        "text": "text-red-500",
        "border": "border-red-500",
        "ring_glow": "shadow-[0_0_30px_rgba(239,68,68,0.2)]",
        "card_glow": "shadow-[0_0_30px_rgba(239,68,68,0.1)]",
    },
    "slate": {
        "text": "text-slate-500",
        "border": "border-slate-600",
        "ring_glow": "",
        "card_glow": "",
    },
}


def grade_theme(grade):
    if grade in ("A", "B"):
        return GRADE_THEMES["green"]
    if grade == "C":
        return GRADE_THEMES["yellow"]
    if grade in ("D", "E", "F"):
        return GRADE_THEMES["red"]
    return GRADE_THEMES["slate"]


def risk_theme(risk):
    if risk == "low":
        return GRADE_THEMES["green"]
    if risk == "medium":
        return GRADE_THEMES["yellow"]
    if risk == "high":
        return GRADE_THEMES["red"]
    return GRADE_THEMES["slate"]


def normalize_url(raw):
    """Return a validated http(s) URL or raise ValueError."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("No URL provided.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{parsed.scheme}'. Only http(s) is allowed.")
    if not parsed.hostname:
        raise ValueError("Could not parse a hostname from that URL.")
    return raw


def resolve_target_ip(host):
    """Resolve host and refuse private/reserved addresses so the scanner can't
    be pointed at loopback, LAN hosts, or cloud metadata endpoints (SSRF).
    ALLOW_PRIVATE_TARGETS=1 disables the check for lab use (e.g. your router)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        raise ValueError(f"Could not resolve '{host}'.")
    addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    if os.environ.get("ALLOW_PRIVATE_TARGETS") != "1":
        for addr in addresses:
            if not addr.is_global:
                raise ValueError(
                    f"'{host}' resolves to a non-public address ({addr}). "
                    "Set ALLOW_PRIVATE_TARGETS=1 to scan private/lab targets.")
    return str(addresses[0])


def safe_fetch(url):
    """GET the target, following redirects manually so every hop passes the
    SSRF guard. Bodies are never read — only status and headers matter here.
    The guard resolves DNS separately from the request itself, so a
    fast-flux/rebinding domain could evade it; fine for scanning public sites,
    not a substitute for network-level egress rules."""
    session = requests.Session()
    try:
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"Refusing redirect to non-http(s) URL: {url}")
            ip_addr = resolve_target_ip(parsed.hostname)
            response = session.get(
                url,
                timeout=10,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": USER_AGENT},
            )
            response.close()
            if not response.is_redirect and not response.is_permanent_redirect:
                return response, ip_addr
            location = response.headers.get("Location")
            if not location:
                return response, ip_addr
            url = urljoin(url, location)
        raise ValueError(f"Target redirected more than {MAX_REDIRECTS} times.")
    finally:
        session.close()


_rate_lock = threading.Lock()
_rate_hits = {}


def rate_limited(client_ip):
    """Sliding-window limiter for the endpoints that spend API credit."""
    now = time.monotonic()
    with _rate_lock:
        hits = [t for t in _rate_hits.get(client_ip, []) if now - t < 60]
        if len(hits) >= RATE_LIMIT_PER_MINUTE:
            _rate_hits[client_ip] = hits
            return True
        hits.append(now)
        _rate_hits[client_ip] = hits
        if len(_rate_hits) > 10_000:  # crude bound; resets everyone's window
            _rate_hits.clear()
        return False


def audit_headers(response_headers):
    """Check the six audited headers case-insensitively (requests gives us a
    CaseInsensitiveDict already)."""
    rows = []
    for name in SECURITY_HEADERS:
        value = response_headers.get(name)
        rows.append({
            "name": name,
            "present": value is not None,
            "value": value or "",
        })
    return rows


def claude_grade(host, rows):
    """Ask Claude for a grade. Returns a dict or None on any failure —
    the caller renders the headers table either way."""
    try:
        from anthropic import Anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        summary_lines = [f"Site: {host}", "", "HTTP security header audit results:"]
        for row in rows:
            if row["present"]:
                summary_lines.append(f"- {row['name']}: PRESENT, value: {row['value']}")
            else:
                summary_lines.append(f"- {row['name']}: MISSING")

        # 30s timeout so a stalled API call degrades to headers-only instead
        # of hanging the request (SDK default is 10 minutes).
        client = Anthropic(api_key=api_key, timeout=30.0)
        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=1024,
            system=CLAUDE_SYSTEM_INSTRUCTION,
            messages=[
                {
                    "role": "user",
                    "content": "\n".join(summary_lines),
                }
            ],
        )

        # Claude may wrap the JSON in prose or a ```json code fence, so slice
        # from the first "{" to the last "}" before parsing.
        response_text = response.content[0].text
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Claude response contained no JSON object")
        data = json.loads(response_text[start : end + 1])

        grade = str(data.get("grade", "")).strip().upper()[:1]
        if grade not in "ABCDEF" or not grade:
            raise ValueError(f"Claude returned an invalid grade: {data.get('grade')!r}")

        findings = []
        for item in data.get("findings") or []:
            status = str(item.get("status", "")).strip()
            findings.append({
                "header": str(item.get("header", "")).strip(),
                "status": status,
                "risk": str(item.get("risk", "")).strip(),
                "fix": str(item.get("fix", "")).strip(),
                "critical": "missing" in status.lower(),
            })

        return {
            "grade": grade,
            "verdict": str(data.get("verdict", "")).strip(),
            "findings": findings,
        }
    except Exception as exc:  # any Claude failure degrades to headers-only
        app.logger.warning("Claude grading unavailable: %s", exc)
        return None


def claude_phish_check(text):
    """Ask Claude to triage a suspicious message/link. Purely passive — the
    pasted URL is never fetched or resolved. Returns a dict or None."""
    try:
        from anthropic import Anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        prompt_lines = ["Suspicious content pasted by the user:", "", text[:8000]]
        urls = URL_RE.findall(text)[:10]
        if urls:
            prompt_lines += ["", "URLs extracted for reference:"]
            for u in urls:
                host = urlparse(u if "://" in u else "https://" + u).hostname or "?"
                prompt_lines.append(f"- {u} (host: {host})")

        client = Anthropic(api_key=api_key, timeout=30.0)
        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=1024,
            system=PHISH_SYSTEM_INSTRUCTION,
            messages=[
                {
                    "role": "user",
                    "content": "\n".join(prompt_lines),
                }
            ],
        )

        # Same JSON extraction as claude_grade().
        response_text = response.content[0].text
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Claude response contained no JSON object")
        data = json.loads(response_text[start : end + 1])

        risk = str(data.get("risk", "")).strip().lower()
        if risk not in ("low", "medium", "high"):
            raise ValueError(f"Claude returned an invalid risk: {data.get('risk')!r}")

        indicators = []
        for item in data.get("indicators") or []:
            severity = str(item.get("severity", "info")).strip().lower()
            if severity not in ("info", "warning", "critical"):
                severity = "info"
            indicators.append({
                "title": str(item.get("title", "")).strip(),
                "severity": severity,
                "detail": str(item.get("detail", "")).strip(),
            })

        return {
            "risk": risk,
            "verdict": str(data.get("verdict", "")).strip(),
            "advice": str(data.get("advice", "")).strip(),
            "indicators": indicators,
            "theme": risk_theme(risk),
        }
    except Exception as exc:
        app.logger.warning("Claude phishing triage unavailable: %s", exc)
        return None


def run_scan(target_url):
    """Fetch the target and build the full scan context for the template."""
    response, ip_addr = safe_fetch(target_url)
    final = urlparse(response.url)
    host = final.hostname or urlparse(target_url).hostname
    rows = audit_headers(response.headers)

    ai = claude_grade(host, rows)

    present = sum(1 for r in rows if r["present"])
    missing = len(rows) - present
    warnings = 0
    if ai:
        warnings = sum(1 for f in ai["findings"] if not f["critical"])

    grade = ai["grade"] if ai else None
    return {
        "host": host,
        "https": final.scheme == "https",
        "ip": ip_addr,
        "port": final.port or (443 if final.scheme == "https" else 80),
        "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "rows": rows,
        "present": present,
        "missing": missing,
        "warnings": warnings,
        "compliance": round(present / len(rows) * 100),
        "ai": ai,
        "grade": grade,
        "theme": grade_theme(grade),
    }


@app.context_processor
def inject_model():
    return {"model": CLAUDE_MODEL}


@app.after_request
def apply_security_headers(response):
    """Practice what we audit. HSTS is intentionally absent — it belongs on
    the TLS-terminating proxy, not on a plain-HTTP local app."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "font-src 'self'; img-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.route("/")
def index():
    return render_template_string(TEMPLATE, scan=None, error=None, target_input="",
                                  active="audit")


@app.route("/scan", methods=["POST"])
def scan():
    raw = request.form.get("url", "")
    if rate_limited(request.remote_addr):
        return render_template_string(
            TEMPLATE, scan=None, target_input=raw, active="audit",
            error="Rate limit exceeded. Try again in a minute."), 429

    try:
        target_url = normalize_url(raw)
    except ValueError as exc:
        return render_template_string(TEMPLATE, scan=None, error=str(exc), target_input=raw,
                                      active="audit")

    try:
        result = run_scan(target_url)
    except ValueError as exc:  # SSRF guard refusal / redirect loop
        return render_template_string(
            TEMPLATE, scan=None, target_input=raw, active="audit",
            error=str(exc))
    except requests.exceptions.Timeout:
        return render_template_string(
            TEMPLATE, scan=None, target_input=raw, active="audit",
            error="The target did not respond within 10 seconds.")
    except requests.exceptions.RequestException:
        return render_template_string(
            TEMPLATE, scan=None, target_input=raw, active="audit",
            error="Failed to reach the target. Check the URL and try again.")
    except Exception:
        app.logger.exception("Unexpected scan failure")
        return render_template_string(
            TEMPLATE, scan=None, target_input=raw, active="audit",
            error="Unexpected scan failure. Check the URL and try again.")

    return render_template_string(TEMPLATE, scan=result, error=None, target_input=raw,
                                  active="audit")


@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    if request.method == "GET":
        return render_template_string(PHISHING_TEMPLATE, result=None, error=None,
                                      message_input="", active="phish")

    text = (request.form.get("message") or "").strip()
    if rate_limited(request.remote_addr):
        return render_template_string(
            PHISHING_TEMPLATE, result=None, message_input=text, active="phish",
            error="Rate limit exceeded. Try again in a minute."), 429
    if not text:
        return render_template_string(
            PHISHING_TEMPLATE, result=None, message_input="", active="phish",
            error="Nothing to analyze. Paste a link or message first.")

    result = claude_phish_check(text)
    if result is None:
        return render_template_string(
            PHISHING_TEMPLATE, result=None, message_input=text, active="phish",
            error="AI analysis unavailable. Check the API key and the server log.")

    return render_template_string(PHISHING_TEMPLATE, result=result, error=None,
                                  message_input=text, active="phish")


@app.route("/headers")
def header_reference():
    return render_template_string(REFERENCE_TEMPLATE, headers=HEADER_REFERENCE,
                                  active="reference")


PAGE_TOP = r"""<!doctype html>
<html lang="en" class="h-full">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>HTTP Security Header Auditor // Lab Console</title>
    <!-- All assets are served same-origin so the CSP can stay 'self'-only. -->
    <link rel="stylesheet" href="/static/tailwind.css">
    <link rel="stylesheet" href="/static/site.css">
    <script src="/static/app.js" defer></script>
  </head>
  <body class="font-sans text-slate-200 min-h-screen flex flex-col selection:bg-blue-600 selection:text-white">
    <!-- Scanline Filter -->
    <div class="scanlines"></div>

    <!-- Header / Navbar -->
    <header class="border-b border-[#30363D] bg-[#0A0C10]/80 backdrop-blur-md sticky top-0 z-50">
      <div class="max-w-6xl mx-auto px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <div class="h-8 w-8 bg-blue-600/10 border border-blue-500/30 flex items-center justify-center rounded shadow-[0_0_15px_rgba(59,130,246,0.1)]">
            <span class="font-mono text-blue-500 font-bold text-sm">&lt;/&gt;</span>
          </div>
          <div>
            <h1 class="font-mono font-black tracking-tighter text-blue-500 text-lg flex items-center gap-2">
              HTTP_SEC_AUDITOR
              <span class="text-xs font-normal text-slate-600">v2.4.0</span>
            </h1>
            <p class="text-[10px] text-slate-500 uppercase tracking-widest font-semibold font-mono">Academic Security Lab Framework</p>
          </div>
        </div>
        <div class="flex items-center gap-4 text-xs font-mono text-slate-500">
          <span class="flex items-center gap-1.5">
            <span class="h-2 w-2 rounded-full bg-emerald-500 inline-block pulse-dot"></span>
            MODE: LIVE_SCAN
          </span>
          <span class="hidden md:inline-block border-l border-[#30363D] h-4"></span>
          <span class="hidden md:inline-block">STORAGE: STATELESS</span>
          <span class="hidden md:inline-block border-l border-[#30363D] h-4"></span>
          <span class="hidden md:inline-block">USER: GUEST_ACADEMIC</span>
        </div>
      </div>
      <!-- Module Tabs -->
      <nav class="max-w-6xl mx-auto px-6 flex gap-6 font-mono text-xs tracking-widest uppercase">
        <a href="/" class="pb-3 border-b-2 transition-colors {{ 'text-blue-500 border-blue-500 font-bold' if active == 'audit' else 'text-slate-500 border-transparent hover:text-slate-300' }}">Header_Audit</a>
        <a href="/phishing" class="pb-3 border-b-2 transition-colors {{ 'text-blue-500 border-blue-500 font-bold' if active == 'phish' else 'text-slate-500 border-transparent hover:text-slate-300' }}">Phishing_Triage</a>
        <a href="/headers" class="pb-3 border-b-2 transition-colors {{ 'text-blue-500 border-blue-500 font-bold' if active == 'reference' else 'text-slate-500 border-transparent hover:text-slate-300' }}">Header_Reference</a>
      </nav>
    </header>
"""

AUDIT_BODY = r"""
    <!-- Main Content Container -->
    <main class="flex-grow max-w-6xl w-full mx-auto px-6 py-8 space-y-8 relative z-10">

      <!-- ========================================== -->
      <!-- SECTION 1: SCAN FORM (Top)                 -->
      <!-- ========================================== -->
      <section id="scan-form" class="bg-[#161B22] border border-[#30363D] rounded-xl p-6 sm:p-8 relative overflow-hidden shadow-2xl">
        <!-- Radial gradient subtle trace -->
        <div class="absolute inset-0 pointer-events-none bg-[radial-gradient(#1B1F23_1px,transparent_1px)] bg-[size:24px_24px] opacity-20"></div>

        <div class="max-w-3xl mx-auto text-center space-y-6 relative z-10">
          <div class="space-y-2">
            <div class="font-mono text-xs text-blue-500 tracking-widest uppercase font-bold">
              // academic security lab module
            </div>
            <h2 class="font-sans text-2xl sm:text-3xl font-black text-white tracking-tight">
              Analyze HTTP Security Headers
            </h2>
            <p class="text-sm text-slate-400 max-w-xl mx-auto">
              Scan target server configurations, audit defensive wrappers, and output AI-vetted vulnerabilities with structural remediation recipes.
            </p>
          </div>

          <!-- The Scan Input Wrapper -->
          <form method="POST" action="/scan" class="relative max-w-2xl mx-auto bg-[#0D1117] border border-[#30363D] focus-within:border-blue-500 rounded-lg p-1.5 flex flex-col sm:flex-row items-stretch gap-2 transition-all duration-300 shadow-lg focus-within:shadow-[0_0_20px_rgba(59,130,246,0.15)]">
            <!-- URL Prefix decoration -->
            <div class="flex items-center px-4 font-mono text-sm text-slate-500 select-none border-r border-[#30363D]/40 sm:mr-1">
              HTTPS://
            </div>
            <!-- Input Text -->
            <input
              type="text"
              name="url"
              placeholder="enter domain (e.g., github.com)"
              value="{{ target_input }}"
              class="flex-grow bg-transparent text-[#E6EDF3] font-mono placeholder-slate-700 focus:outline-none px-3 py-3 text-sm sm:text-base w-full"
            />
            <!-- Action Button -->
            <button
              type="submit"
              class="bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold px-8 py-3 rounded text-sm tracking-widest uppercase transition-all duration-150 flex items-center justify-center gap-2 hover:shadow-[0_0_15px_rgba(59,130,246,0.3)] active:scale-[0.98]"
            >
              <span>Execute_Scan</span>
            </button>
          </form>

          <!-- Under-bar info tags -->
          <div class="flex flex-wrap items-center justify-center gap-y-2 gap-x-6 text-xs font-mono text-slate-500">
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> OWASP Compliant
            </span>
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> RFC Vetted Checkers
            </span>
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> Local Sandboxed Verification
            </span>
          </div>
        </div>
      </section>

      {% if error %}
      <!-- ========================================== -->
      <!-- ERROR BANNER                               -->
      <!-- ========================================== -->
      <section id="error-banner" class="bg-red-950/50 border-b border-red-500/50 p-4 text-center text-red-200 text-sm font-mono z-20 shadow-[0_0_15px_rgba(239,68,68,0.15)]">
        [ERROR]: {{ error|upper }}
      </section>
      {% endif %}

      {% if scan %}
      <!-- ========================================== -->
      <!-- SECTION 2: RESULTS (Below)                 -->
      <!-- ========================================== -->
      <section id="results" class="space-y-6">

        <!-- target system specification block -->
        <div class="bg-[#0D1117] border border-[#30363D] rounded-lg px-6 py-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div class="space-y-1">
            <div class="font-mono text-xs text-slate-500 uppercase tracking-widest">// current evaluation target</div>
            <div class="flex items-center gap-2">
              <span class="font-mono text-lg font-bold text-[#E6EDF3]">{{ scan.host }}</span>
              {% if scan.https %}
              <span class="h-2 w-2 rounded-full bg-emerald-500 inline-block pulse-dot"></span>
              <span class="text-xs text-emerald-500 font-mono bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">HTTPS OK</span>
              {% else %}
              <span class="h-2 w-2 rounded-full bg-red-500 inline-block pulse-dot"></span>
              <span class="text-xs text-red-500 font-mono bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">PLAINTEXT HTTP</span>
              {% endif %}
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs font-mono text-slate-400">
            <div>
              <span class="text-slate-500">IP_ADDR:</span> <span class="text-[#E6EDF3]">{{ scan.ip }}</span>
            </div>
            <div class="hidden md:block text-slate-700">|</div>
            <div>
              <span class="text-slate-500">PORT:</span> <span class="text-[#E6EDF3]">{{ scan.port }} ({{ 'TLS' if scan.https else 'PLAINTEXT' }})</span>
            </div>
            <div class="hidden md:block text-slate-700">|</div>
            <div>
              <span class="text-slate-500">SCAN_TIME:</span> <span class="text-[#E6EDF3]">{{ scan.scan_time }}</span>
            </div>
          </div>
        </div>

        <!-- Grade, Overview, Metrics Layout -->
        <div class="grid grid-cols-1 md:grid-cols-12 gap-6">

          <!-- Grade Badge Widget (4-cols) -->
          <div id="grade-badge" class="bg-[#0D1117] border border-[#30363D] rounded-xl p-8 flex flex-col justify-between relative overflow-hidden shadow-lg md:col-span-4 {{ scan.theme.card_glow }}">
            <div class="absolute top-0 right-0 p-3 font-mono text-[9px] text-slate-600 select-none tracking-[0.2em] uppercase font-bold">Security Rating</div>

            <div class="space-y-1">
              <div class="font-mono text-[10px] {{ scan.theme.text }} uppercase tracking-widest font-bold">// evaluation index</div>
              <h3 class="font-mono font-bold text-slate-400 text-xs uppercase tracking-wider">Security Rating</h3>
            </div>

            <!-- Huge custom letter grade representation -->
            <div class="my-6 flex items-center justify-center">
              <div class="relative flex items-center justify-center">
                <!-- Grade Letter -->
                <div class="w-32 h-32 rounded-full flex items-center justify-center text-6xl font-black border-4 {{ scan.theme.border }} {{ scan.theme.text }} {{ scan.theme.ring_glow }}">
                  {{ scan.grade or '?' }}
                </div>
              </div>
            </div>

            <!-- Stats strip -->
            <div class="border-t border-[#30363D] pt-4 flex justify-between items-center text-xs font-mono">
              <div class="text-center">
                <div class="text-emerald-500 text-sm font-bold">{{ scan.present }}</div>
                <div class="text-slate-500 text-[10px]">PASSED</div>
              </div>
              <div class="h-6 w-px bg-[#30363D]"></div>
              <div class="text-center">
                <div class="text-red-500 text-sm font-bold">{{ scan.missing }}</div>
                <div class="text-slate-500 text-[10px]">MISSING</div>
              </div>
              <div class="h-6 w-px bg-[#30363D]"></div>
              <div class="text-center">
                <div class="text-blue-500 text-sm font-bold">{{ scan.warnings }}</div>
                <div class="text-slate-500 text-[10px]">WARNING</div>
              </div>
            </div>
          </div>

          <!-- Verdict & AI Report Card Block (8-cols) -->
          <div class="bg-[#0D1117] border border-[#30363D] rounded-xl p-8 md:col-span-8 flex flex-col justify-between shadow-lg">
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <div class="font-mono text-xs text-blue-500 uppercase tracking-wider font-bold">// artificial intelligence verdict</div>
                <span class="text-[10px] font-mono text-slate-600">LLM_ENGINE: {{ model }}</span>
              </div>

              <!-- Verdict Text Wrapper -->
              {% if scan.ai %}
              <div id="verdict" class="bg-[#161B22] border-l-4 {{ scan.theme.border }} p-5 rounded-r font-sans text-sm text-slate-300 leading-relaxed italic">
                "{{ scan.ai.verdict }}"
              </div>

              <!-- Academic context note -->
              <p class="text-xs text-slate-400 leading-relaxed">
                Grade and remediation guidance are generated by Claude from the live response headers of the final (post-redirect) URL. Validate every suggested header in a staging environment before deploying to production.
              </p>
              {% else %}
              <div id="verdict" class="bg-[#161B22] border-l-4 border-slate-600 p-5 rounded-r font-sans text-sm text-slate-400 leading-relaxed italic">
                AI grading is unavailable for this scan. The headers table below still reflects the live audit.
              </div>

              <p class="text-xs text-slate-400 leading-relaxed">
                The Claude request failed or no ANTHROPIC_API_KEY is configured. Set the environment variable and re-run the scan to receive a letter grade, verdict, and remediation recipes.
              </p>
              {% endif %}
            </div>

            <div class="mt-6 border-t border-[#30363D] pt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
              <span class="text-slate-500">VULNERABILITY EXP: {{ scan.ai.findings|length if scan.ai else scan.missing }} DETECTED</span>
              {% if scan.missing > 0 or (scan.ai and scan.ai.findings) %}
              <span class="{{ scan.theme.text }} flex items-center gap-1">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-alert"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8.24-2.28a1 1 0 0 1 .48 0l8.24 2.28A1 1 0 0 1 20 6v7z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>
                ACTION REQUIRED: REVIEW FINDINGS
              </span>
              {% else %}
              <span class="text-emerald-500 flex items-center gap-1">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-alert"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8.24-2.28a1 1 0 0 1 .48 0l8.24 2.28A1 1 0 0 1 20 6v7z"/></svg>
                NO ACTION REQUIRED
              </span>
              {% endif %}
            </div>
          </div>
        </div>

        <!-- Headers Table Wrapper -->
        <div class="bg-[#0D1117] border border-[#30363D] rounded-xl overflow-hidden shadow-lg">
          <div class="px-6 py-4 border-b border-[#30363D] flex items-center justify-between bg-[#161B22]">
            <div class="flex items-center gap-2">
              <span class="h-2 w-2 rounded-full bg-blue-500"></span>
              <h3 class="font-mono text-xs font-bold text-slate-400 uppercase tracking-wider">AUDITED_HTTP_SECURITY_HEADERS</h3>
            </div>
            <span class="text-xs font-mono text-slate-500">RFC_COMPLIANCE: {{ scan.compliance }}%</span>
          </div>

          <div class="overflow-x-auto">
            <table id="headers-table" class="w-full text-left border-collapse">
              <thead>
                <tr class="border-b border-[#30363D] text-[10px] font-mono text-slate-500 bg-[#161B22] uppercase tracking-wider font-bold">
                  <th class="px-6 py-4">Security Header</th>
                  <th class="px-6 py-4">Status</th>
                  <th class="px-6 py-4">Raw Value</th>
                </tr>
              </thead>
              <tbody class="font-mono text-sm">
                {% for row in scan.rows %}
                <tr class="{{ 'border-b border-[#21262d] ' if not loop.last }}hover:bg-white/5 {{ '' if row.present else 'bg-red-950/10 ' }}transition-colors">
                  <td class="px-6 py-4 font-bold {{ 'text-blue-400' if row.present else 'text-red-400' }}">{{ row.name }}</td>
                  <td class="px-6 py-4">
                    {% if row.present %}
                    <span class="text-emerald-500">[✓] PRESENT</span>
                    {% else %}
                    <span class="text-red-500 font-bold">[✗] MISSING</span>
                    {% endif %}
                  </td>
                  {% if row.present %}
                  <td class="px-6 py-4 text-slate-500 truncate max-w-xs md:max-w-md" title="{{ row.value }}">
                    {{ row.value }}
                  </td>
                  {% else %}
                  <td class="px-6 py-4 text-slate-600">
                    n/a
                  </td>
                  {% endif %}
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="px-6 py-3 border-t border-[#30363D] bg-[#0D1117] text-[10px] font-mono text-slate-600 text-center sm:text-left">
            LIVE_SCAN: FINAL RESPONSE HEADERS AFTER REDIRECTS // NOTHING STORED
          </div>
        </div>

        {% if scan.ai and scan.ai.findings %}
        <!-- Findings & Remediation Cards Section -->
        <div class="space-y-4">
          <div class="flex items-center gap-2 px-2">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="text-red-400 lucide lucide-shield-alert"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8.24-2.28a1 1 0 0 1 .48 0l8.24 2.28A1 1 0 0 1 20 6v7z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>
            <h3 class="font-mono text-xs font-bold text-slate-400 uppercase tracking-widest">// DETAILED_FINDINGS_AND_REMEDIATION</h3>
          </div>

          <!-- Findings Container -->
          <div id="findings" class="grid grid-cols-1 md:grid-cols-2 gap-6">
            {% for f in scan.ai.findings %}
            <div class="bg-[#161B22] border-l-4 {{ 'border-red-500' if f.critical else 'border-yellow-500' }} p-6 rounded-r-xl relative overflow-hidden shadow-lg space-y-4">
              <!-- Risk Level Flag -->
              <div class="absolute top-0 right-0 {{ 'bg-red-950 text-red-400' if f.critical else 'bg-yellow-950 text-yellow-500' }} border-l border-b border-[#30363D] font-mono font-bold text-[10px] px-3 py-1 uppercase tracking-wider rounded-bl">
                {{ 'Critical' if f.critical else 'Warning' }}: {{ f.header }}
              </div>

              <div class="space-y-1">
                <div class="font-mono text-[10px] {{ 'text-red-400' if f.critical else 'text-yellow-500' }} uppercase tracking-widest">// anomaly_{{ '%02d'|format(loop.index) }}</div>
                <h4 class="font-mono text-base font-bold text-white flex items-center gap-2">
                  {{ f.header }}
                </h4>
              </div>

              <!-- Risk Narrative -->
              <div class="text-xs text-slate-400 space-y-2 leading-relaxed">
                <p>
                  {{ f.risk }}
                </p>
              </div>

              <!-- Remediation Codeblock -->
              <div class="space-y-1" data-copy-block>
                <div class="flex items-center justify-between text-[10px] font-mono text-slate-500 px-1">
                  <span>REMEDY_HEADER_SYNTAX</span>
                  <span data-copy class="hover:text-emerald-400 cursor-pointer flex items-center gap-1 transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                    COPY_FIX
                  </span>
                </div>
                <div class="bg-black/40 p-3 font-mono text-[10px] text-emerald-400 rounded border border-white/10 overflow-x-auto">
                  <code>{{ f.fix }}</code>
                </div>
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
        {% endif %}

      </section>
      {% endif %}

    </main>
"""

PAGE_BOTTOM = r"""
    <!-- Footer -->
    <footer class="border-t border-[#30363D] bg-[#0D1117] py-8 mt-12 text-xs font-mono text-slate-600">
      <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-center sm:text-left">
        <div class="flex items-center gap-2 justify-center sm:justify-start">
          <span class="text-blue-500">[#]</span>
          <span>HTTP_SEC_AUDITOR // ACADEMIC USE ONLY</span>
        </div>
        <div class="tracking-wider">
          STATELESS_SESSION // NO SCAN DATA RETAINED
        </div>
      </div>
    </footer>
  </body>
</html>
"""

PHISHING_BODY = r"""
    <!-- Main Content Container -->
    <main class="flex-grow max-w-6xl w-full mx-auto px-6 py-8 space-y-8 relative z-10">

      <!-- ========================================== -->
      <!-- SECTION 1: TRIAGE FORM (Top)               -->
      <!-- ========================================== -->
      <section id="phish-form" class="bg-[#161B22] border border-[#30363D] rounded-xl p-6 sm:p-8 relative overflow-hidden shadow-2xl">
        <div class="absolute inset-0 pointer-events-none bg-[radial-gradient(#1B1F23_1px,transparent_1px)] bg-[size:24px_24px] opacity-20"></div>

        <div class="max-w-3xl mx-auto text-center space-y-6 relative z-10">
          <div class="space-y-2">
            <div class="font-mono text-xs text-blue-500 tracking-widest uppercase font-bold">
              // phishing triage module
            </div>
            <h2 class="font-sans text-2xl sm:text-3xl font-black text-white tracking-tight">
              Analyze Suspicious Links &amp; Messages
            </h2>
            <p class="text-sm text-slate-400 max-w-xl mx-auto">
              Paste a link, SMS, or email text below. Analysis is fully passive — the link is never opened, fetched, or resolved.
            </p>
          </div>

          <!-- The Triage Input Wrapper -->
          <form method="POST" action="/phishing" class="max-w-2xl mx-auto space-y-3">
            <div class="bg-[#0D1117] border border-[#30363D] focus-within:border-blue-500 rounded-lg p-1.5 transition-all duration-300 shadow-lg focus-within:shadow-[0_0_20px_rgba(59,130,246,0.15)]">
              <textarea
                name="message"
                rows="6"
                placeholder="paste the suspicious message or URL here…"
                class="w-full bg-transparent text-[#E6EDF3] font-mono placeholder-slate-700 focus:outline-none px-3 py-3 text-sm resize-y">{{ message_input }}</textarea>
            </div>
            <button
              type="submit"
              class="w-full sm:w-auto bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold px-8 py-3 rounded text-sm tracking-widest uppercase transition-all duration-150 hover:shadow-[0_0_15px_rgba(59,130,246,0.3)] active:scale-[0.98]"
            >
              Analyze_Threat
            </button>
          </form>

          <!-- Under-bar info tags -->
          <div class="flex flex-wrap items-center justify-center gap-y-2 gap-x-6 text-xs font-mono text-slate-500">
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> Passive Analysis
            </span>
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> Link Never Opened
            </span>
            <span class="flex items-center gap-1">
              <span class="text-blue-500">[✓]</span> Nothing Stored
            </span>
          </div>
        </div>
      </section>

      {% if error %}
      <!-- ERROR BANNER -->
      <section id="error-banner" class="bg-red-950/50 border-b border-red-500/50 p-4 text-center text-red-200 text-sm font-mono z-20 shadow-[0_0_15px_rgba(239,68,68,0.15)]">
        [ERROR]: {{ error|upper }}
      </section>
      {% endif %}

      {% if result %}
      <!-- ========================================== -->
      <!-- SECTION 2: TRIAGE RESULTS                  -->
      <!-- ========================================== -->
      <section id="phish-results" class="space-y-6">

        <div class="grid grid-cols-1 md:grid-cols-12 gap-6">

          <!-- Risk Badge Widget (4-cols) -->
          <div id="risk-badge" class="bg-[#0D1117] border border-[#30363D] rounded-xl p-8 flex flex-col justify-between relative overflow-hidden shadow-lg md:col-span-4 {{ result.theme.card_glow }}">
            <div class="absolute top-0 right-0 p-3 font-mono text-[9px] text-slate-600 select-none tracking-[0.2em] uppercase font-bold">Threat Rating</div>

            <div class="space-y-1">
              <div class="font-mono text-[10px] {{ result.theme.text }} uppercase tracking-widest font-bold">// threat index</div>
              <h3 class="font-mono font-bold text-slate-400 text-xs uppercase tracking-wider">Risk Level</h3>
            </div>

            <div class="my-6 flex items-center justify-center">
              <div class="w-32 h-32 rounded-full flex items-center justify-center text-2xl font-black border-4 {{ result.theme.border }} {{ result.theme.text }} {{ result.theme.ring_glow }} uppercase">
                {{ result.risk }}
              </div>
            </div>

            <div class="border-t border-[#30363D] pt-4 text-center text-xs font-mono text-slate-500">
              {{ result.indicators|length }} INDICATOR(S) DETECTED
            </div>
          </div>

          <!-- Verdict & Advice Block (8-cols) -->
          <div class="bg-[#0D1117] border border-[#30363D] rounded-xl p-8 md:col-span-8 flex flex-col justify-between shadow-lg">
            <div class="space-y-4">
              <div class="flex items-center justify-between">
                <div class="font-mono text-xs text-blue-500 uppercase tracking-wider font-bold">// artificial intelligence verdict</div>
                <span class="text-[10px] font-mono text-slate-600">LLM_ENGINE: {{ model }}</span>
              </div>

              <div id="phish-verdict" class="bg-[#161B22] border-l-4 {{ result.theme.border }} p-5 rounded-r font-sans text-sm text-slate-300 leading-relaxed italic">
                "{{ result.verdict }}"
              </div>

              {% if result.advice %}
              <div class="bg-[#161B22] border border-[#30363D] p-5 rounded text-xs text-slate-400 leading-relaxed">
                <span class="font-mono text-[10px] text-emerald-500 uppercase tracking-widest font-bold block mb-2">// recommended action</span>
                {{ result.advice }}
              </div>
              {% endif %}

              <p class="text-xs text-slate-400 leading-relaxed">
                Triage is generated by Claude from the pasted text only. When in doubt, do not click the link — navigate to the organization's site by typing its address yourself.
              </p>
            </div>
          </div>
        </div>

        {% if result.indicators %}
        <!-- Indicators Section -->
        <div class="space-y-4">
          <div class="flex items-center gap-2 px-2">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="text-red-400 lucide lucide-shield-alert"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8.24-2.28a1 1 0 0 1 .48 0l8.24 2.28A1 1 0 0 1 20 6v7z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>
            <h3 class="font-mono text-xs font-bold text-slate-400 uppercase tracking-widest">// DETECTED_INDICATORS</h3>
          </div>

          <div id="indicators" class="grid grid-cols-1 md:grid-cols-2 gap-6">
            {% for ind in result.indicators %}
            <div class="bg-[#161B22] border-l-4 {{ 'border-red-500' if ind.severity == 'critical' else ('border-yellow-500' if ind.severity == 'warning' else 'border-blue-500') }} p-6 rounded-r-xl relative overflow-hidden shadow-lg space-y-3">
              <div class="absolute top-0 right-0 {{ 'bg-red-950 text-red-400' if ind.severity == 'critical' else ('bg-yellow-950 text-yellow-500' if ind.severity == 'warning' else 'bg-blue-950 text-blue-400') }} border-l border-b border-[#30363D] font-mono font-bold text-[10px] px-3 py-1 uppercase tracking-wider rounded-bl">
                {{ ind.severity }}
              </div>

              <div class="space-y-1">
                <div class="font-mono text-[10px] text-slate-500 uppercase tracking-widest">// indicator_{{ '%02d'|format(loop.index) }}</div>
                <h4 class="font-mono text-base font-bold text-white">{{ ind.title }}</h4>
              </div>

              <div class="text-xs text-slate-400 leading-relaxed">
                <p>{{ ind.detail }}</p>
              </div>
            </div>
            {% endfor %}
          </div>
        </div>
        {% endif %}

      </section>
      {% endif %}

    </main>
"""

REFERENCE_BODY = r"""
    <!-- Main Content Container -->
    <main class="flex-grow max-w-6xl w-full mx-auto px-6 py-8 space-y-8 relative z-10">

      <!-- ========================================== -->
      <!-- HEADER REFERENCE                           -->
      <!-- ========================================== -->
      <section id="reference-intro" class="bg-[#161B22] border border-[#30363D] rounded-xl p-6 sm:p-8 relative overflow-hidden shadow-2xl">
        <div class="absolute inset-0 pointer-events-none bg-[radial-gradient(#1B1F23_1px,transparent_1px)] bg-[size:24px_24px] opacity-20"></div>
        <div class="max-w-3xl mx-auto text-center space-y-2 relative z-10">
          <div class="font-mono text-xs text-blue-500 tracking-widest uppercase font-bold">
            // security header reference module
          </div>
          <h2 class="font-sans text-2xl sm:text-3xl font-black text-white tracking-tight">
            The Six Audited Headers, Explained
          </h2>
          <p class="text-sm text-slate-400 max-w-xl mx-auto">
            What each header does, the attack it blocks, and a safe starting value you can copy.
          </p>
        </div>
      </section>

      <section id="reference-cards" class="grid grid-cols-1 md:grid-cols-2 gap-6">
        {% for h in headers %}
        <div class="bg-[#161B22] border-l-4 border-blue-500 p-6 rounded-r-xl relative overflow-hidden shadow-lg space-y-4">
          <div class="absolute top-0 right-0 bg-blue-950 text-blue-400 border-l border-b border-[#30363D] font-mono font-bold text-[10px] px-3 py-1 uppercase tracking-wider rounded-bl">
            {{ h.defends }}
          </div>

          <div class="space-y-1">
            <div class="font-mono text-[10px] text-slate-500 uppercase tracking-widest">// header_{{ '%02d'|format(loop.index) }}</div>
            <h4 class="font-mono text-base font-bold text-white">{{ h.name }}</h4>
          </div>

          <div class="text-xs text-slate-400 space-y-2 leading-relaxed">
            <p>{{ h.what }}</p>
            <p><span class="text-red-400 font-mono font-bold">ATTACK:</span> {{ h.attack }}</p>
          </div>

          <div class="space-y-1" data-copy-block>
            <div class="flex items-center justify-between text-[10px] font-mono text-slate-500 px-1">
              <span>SAFE_STARTING_VALUE</span>
              <span data-copy class="hover:text-emerald-400 cursor-pointer flex items-center gap-1 transition-colors">
                <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-copy"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
                COPY
              </span>
            </div>
            <div class="bg-black/40 p-3 font-mono text-[10px] text-emerald-400 rounded border border-white/10 overflow-x-auto">
              <code>{{ h.example }}</code>
            </div>
          </div>

          <p class="text-[10px] font-mono text-slate-600">{{ h.note }}</p>
        </div>
        {% endfor %}
      </section>

    </main>
"""

TEMPLATE = PAGE_TOP + AUDIT_BODY + PAGE_BOTTOM
PHISHING_TEMPLATE = PAGE_TOP + PHISHING_BODY + PAGE_BOTTOM
REFERENCE_TEMPLATE = PAGE_TOP + REFERENCE_BODY + PAGE_BOTTOM


if __name__ == "__main__":
    # threaded=True so a slow scan doesn't block other page loads/submits.
    # This is Flask's dev server — for anything beyond localhost use gunicorn
    # (see Dockerfile).
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), threaded=True)
