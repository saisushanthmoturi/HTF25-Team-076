#!/usr/bin/env python3
"""
Gemini-powered Demo Log Generator
================================
Generates realistic Tomcat access logs (combined/common formats)
including both benign user activity (login, browse, cart, checkout)
and malicious traffic (SQLi, XSS, Path Traversal, Command Injection,
Basic DDoS-like bursts), then appends them to a log file for the
Streamlit dashboard.

Setup
-----
- pip install google-generativeai
- export GOOGLE_API_KEY="<your key>"

Usage
-----
from gemini_log_generator import generate_and_append_demo_logs
count = generate_and_append_demo_logs("./demo_access.log", num_lines=150)
print(f"Appended {count} lines to demo_access.log")
"""
from __future__ import annotations
import os
import random
from datetime import datetime, timedelta
from typing import List, Optional

# Optional: Only import when an API key exists
def _get_gemini_model():
    try:
        import google.generativeai as genai  # type: ignore
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            return None, "Missing GOOGLE_API_KEY"
        genai.configure(api_key=api_key)
        # Fast, good for structured text
        model = genai.GenerativeModel("gemini-1.5-flash")
        return model, None
    except Exception as e:
        return None, str(e)

TOMCAT_COMBINED_EXAMPLE = (
    '192.168.1.10 - - [26/Oct/2025:10:30:00 +0000] "GET /ecommerce-app/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
)

ATTACK_HINTS = [
    "SQL Injection (use tokens like ' OR 1=1--, UNION SELECT, DROP TABLE, SLEEP(), benchmark())",
    "XSS (use <script>, onerror=, javascript:, alert())",
    "Path Traversal (use ../, %2e%2e%2f, /etc/passwd, ..\\)",
    "Command Injection (use ; cat /etc/passwd, && id, | whoami)",
    "Basic DDoS-like burst (many GETs to same endpoint with rotating IPs; some 429/503)"
]

BENIGN_HINTS = [
    "Login, logout, profile view",
    "Product listing and search",
    "Add to cart, update cart, checkout",
    "API calls under /rest-api-app/api/*",
    "CMS browsing under /blog-cms-app/*"
]

APPS = ["/ecommerce-app", "/rest-api-app", "/blog-cms-app"]

PROMPT_TEMPLATE = """
You are emulating Tomcat access logs in combined format. Output ONLY raw log lines, no markdown, no code fences, no numbering.

Requirements:
- Exactly {num_lines} lines.
- Timestamp window: from {start_ts} to {end_ts} (UTC +0000) in Apache format: [DD/Mon/YYYY:HH:MM:SS +0000].
- Mix of IPv4 and IPv6 loopback is acceptable but prefer private IPv4 ranges.
- Methods: GET, POST, PUT, DELETE (mostly GET).
- Status codes: 200/201/304 for normal; 403/404/400/500 for attacks; include a few 429/503 for burst traffic.
- User-Agents: realistic (Chrome/Safari/curl) plus a few tooling UAs (sqlmap/AttackBot).
- Paths should target these Java apps: /ecommerce-app, /rest-api-app, /blog-cms-app.
- Use combined format fields: ip - - [ts] "METHOD PATH HTTP/1.1" status bytes "-" "UA".

Distribution:
- ~60% benign normal actions: {benign_hints}
- ~40% attacks covering: {attack_hints}
- Include query strings for searches and attacks.
- Include some entries explicitly BLOCKED by app server with status 403.

Important:
- Do NOT include any commentary.
- Do NOT wrap output in code fences.
- Ensure each line is a valid Tomcat combined access log.

Examples of style (do not repeat these exact lines):
{example}
"""


def _build_prompt(num_lines: int) -> str:
    now = datetime.utcnow()
    start = now - timedelta(minutes=30)
    return PROMPT_TEMPLATE.format(
        num_lines=num_lines,
        start_ts=start.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        end_ts=now.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        benign_hints=", ".join(BENIGN_HINTS),
        attack_hints=", ".join(ATTACK_HINTS),
        example=TOMCAT_COMBINED_EXAMPLE,
    )


def _clean_lines(text: str) -> List[str]:
    lines = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("```"):
            # Skip code fences if present
            continue
        # Ensure line contains an HTTP method and quotes
        if '"' in s and "HTTP/" in s:
            lines.append(s)
    return lines


def _fallback_lines(num_lines: int) -> List[str]:
    """Deterministic fallback without Gemini (covers benign + attacks)."""
    base_time = datetime.utcnow()
    uas = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "curl/7.88.1",
        "AttackBot/1.0",
        "sqlmap/1.7"
    ]
    benign_paths = [
        "/ecommerce-app/",
        "/ecommerce-app/products",
        "/ecommerce-app/search.jsp?query=laptop",
        "/ecommerce-app/cart/add?id=123",
        "/ecommerce-app/checkout",
        "/rest-api-app/",
        "/rest-api-app/api/status",
        "/rest-api-app/api/users?limit=10",
        "/blog-cms-app/",
        "/blog-cms-app/posts?id=42",
    ]
    attack_paths = [
        "/ecommerce-app/search.jsp?query=' OR 1=1--",
        "/ecommerce-app/search.jsp?query=<script>alert('xss')</script>",
        "/ecommerce-app/admin/../../../etc/passwd",
        "/rest-api-app/api/users?id=1'; DROP TABLE users;--",
        "/blog-cms-app/upload.php?file=../../../etc/shadow",
        "/rest-api-app/api/search?q=; cat /etc/passwd",
        "/ecommerce-app/products.jsp?cat=1 AND SLEEP(5)--",
        "/blog-cms-app/index.php?page=../../../../../../etc/passwd",
    ]
    out: List[str] = []
    for i in range(num_lines):
        ts = (base_time - timedelta(seconds=(num_lines - i) * 5)).strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
        ua = random.choice(uas)
        if random.random() < 0.6:
            path = random.choice(benign_paths)
            status = random.choice([200, 200, 200, 201, 304])
            size = random.randint(800, 4000)
        else:
            path = random.choice(attack_paths)
            status = random.choice([403, 400, 404, 500, 200])
            size = random.randint(200, 1500)
        line = f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        out.append(line)
    return out


def generate_and_append_demo_logs(
    file_path: str = "./demo_access.log",
    num_lines: int = 120,
    categories: Optional[List[str]] = None,
) -> int:
    """Generate logs with Gemini (or fallback) and append to a file.

    Args:
        file_path: Target log file (Tomcat combined format preferred).
        num_lines: Number of lines to append.
        categories: Optional list to bias content, e.g. ["benign","sqli","xss","traversal","cmd","ddos"].

    Returns:
        Count of lines appended.
    """
    model, err = _get_gemini_model()
    lines: List[str] = []

    if model is not None:
        # Build a bias string for the prompt (categories are hints only)
        bias = ""
        if categories:
            bias = "\nBias towards categories: " + ", ".join(categories)
        prompt = _build_prompt(num_lines) + bias
        try:
            resp = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 0.25,
                    "max_output_tokens": 8192,
                    "top_p": 0.95,
                    "top_k": 40,
                },
            )
            text = getattr(resp, "text", "") or ""
            lines = _clean_lines(text)
        except Exception:
            lines = []

    # Fall back or fix count
    if not lines or len(lines) < int(num_lines * 0.8):
        # Extend with fallback to reach desired volume
        needed = num_lines - len(lines)
        if needed <= 0:
            needed = 0
        lines.extend(_fallback_lines(max(needed, 0)))

    # Trim to exactly num_lines
    lines = lines[:num_lines]

    # Append to file
    appended = 0
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln.rstrip("\n") + "\n")
            appended += 1
    return appended


if __name__ == "__main__":
    count = generate_and_append_demo_logs("./demo_access.log", num_lines=150)
    print(f"Appended {count} lines to ./demo_access.log")
