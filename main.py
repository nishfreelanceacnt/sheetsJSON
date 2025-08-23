import os, time, io, csv, json, requests, datetime, re, hashlib, smtplib, uuid, secrets
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage
from urllib.parse import urlparse, parse_qs, urlunsplit

from fastapi import FastAPI, HTTPException, Query, Header, Request, Response, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response as FastAPIResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from uvicorn import run as uvicorn_run
from fastapi.responses import RedirectResponse

import sqlite3
try:
    import psycopg2
    HAS_PG = True
except Exception:
    HAS_PG = False

import stripe

# ---------- Optional: Sentry ----------
SENTRY_DSN = os.getenv("SENTRY_DSN","").strip()
if SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.05)
    except Exception:
        pass

# ---------- App ----------
app = FastAPI(
    title="SheetsJSON",
    version="0.13.0",
    openapi_tags=[
        {"name": "API", "description": "Convert Google Sheets CSV → JSON"},
        {"name": "Account", "description": "Usage & limits"},
        {"name": "Admin", "description": "Key management"},
        {"name": "Billing", "description": "Stripe checkout & webhook"},
        {"name": "Pages", "description": "Public pages"},
        {"name": "SEO", "description": "Robots & sitemap"},
    ],
)
app.add_middleware(GZipMiddleware)

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")
cors_origins = ["*"] if CORS_ALLOW_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_methods=["*"], allow_headers=["*"])

# ---------- Config ----------
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", "300"))
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")

# Storage backends
KEYS_BACKEND = os.getenv("KEYS_BACKEND", "db").lower()   # 'db' or 'file'
KEYS_PATH = os.getenv("KEYS_PATH", "keys.json")

USAGE_DB = os.getenv("USAGE_DB_PATH", "usage.db")
DATABASE_URL = os.getenv("DATABASE_URL")
DB_IS_PG = bool(DATABASE_URL and DATABASE_URL.startswith("postgres"))

# Key requests
KEY_REQUEST_MODE = os.getenv("KEY_REQUEST_MODE", "file")  # 'file' or 'email'
KEY_REQUEST_FILE = os.getenv("KEY_REQUEST_FILE", "key_requests.jsonl")
KEY_AUTO_ISSUE = os.getenv("KEY_AUTO_ISSUE", "true").lower() in ("1", "true", "yes")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
KEY_REQUEST_TO = os.getenv("KEY_REQUEST_TO", SMTP_USER)

# Admin + rate-limit
ADMIN_USER = os.getenv("ADMIN_USER") or "admin"
ADMIN_PASS = os.getenv("ADMIN_PASS") or "change-me"
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "90"))

# Plans
PLANS = {
    "free": {"price": 0, "monthly_limit": 200,   "label": "Free"},
    "pro":  {"price": 9, "monthly_limit": 5000,  "label": "Pro"},
    "plus": {"price": 19,"monthly_limit": 25000, "label": "Plus"},
}

# Stripe config
STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY")        # sk_test_...
STRIPE_PRICE_PRO      = os.getenv("STRIPE_PRICE_PRO")         # price_...
STRIPE_PRICE_PLUS     = os.getenv("STRIPE_PRICE_PLUS")        # price_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")    # whsec_...
PUBLIC_BASE_URL       = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
STRIPE_AUTOMATIC_TAX  = os.getenv("STRIPE_AUTOMATIC_TAX", "0").lower() in ("1","true","yes","on")
CANCEL_DOWNGRADE_PLAN = os.getenv("CANCEL_DOWNGRADE_PLAN", "free").lower()

SUBSCRIBE_ENABLED = bool(STRIPE_SECRET_KEY and STRIPE_PRICE_PRO and STRIPE_PRICE_PLUS and PUBLIC_BASE_URL)
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# --- Analytics / SEO tokens ---
PLAUSIBLE_DOMAIN = os.getenv("PLAUSIBLE_DOMAIN", "").strip()
GOOGLE_SITE_VERIFICATION = os.getenv("GOOGLE_SITE_VERIFICATION","").strip()

PUBLIC_HOST = ""
try:
    if PUBLIC_BASE_URL:
        PUBLIC_HOST = urlparse(PUBLIC_BASE_URL).netloc
except Exception:
    PUBLIC_HOST = ""

def _analytics_snippet() -> str:
    if not PLAUSIBLE_DOMAIN:
        return ""
    return '<script defer data-domain="' + PLAUSIBLE_DOMAIN + '" src="https://plausible.io/js/script.js"></script>'

def _google_verify_snippet() -> str:
    if not GOOGLE_SITE_VERIFICATION:
        return ""
    return '<meta name="google-site-verification" content="' + GOOGLE_SITE_VERIFICATION + '"/>'

# ---------- Security headers ----------
class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        # Allow Plausible if configured
        if PLAUSIBLE_DOMAIN:
            resp.headers["Content-Security-Policy"] = (
                        "default-src 'self'; "
                        "img-src 'self' data:; "
                        "style-src 'self' 'unsafe-inline'; "
                        "script-src 'self' 'unsafe-inline' https://plausible.io; "
                        "connect-src 'self' https://plausible.io;"
                        )

        return resp

app.add_middleware(SecurityHeaders)

# ---------- In-memory cache & rate limit ----------
_cache: Dict[str, Dict] = {}
_rl: Dict[str, List[float]] = {}

# ---------- DB helpers ----------
def db_conn():
    if DB_IS_PG:
        if not HAS_PG:
            raise RuntimeError("psycopg2 not installed; needed for Postgres")
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(USAGE_DB)

def db_init():
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS usage (
                    api_key TEXT NOT NULL,
                    period  TEXT NOT NULL,
                    count   INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (api_key, period)
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    api_key TEXT PRIMARY KEY,
                    plan TEXT NOT NULL,
                    monthly_limit INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    session_id  TEXT PRIMARY KEY,
                    email       TEXT,
                    plan        TEXT NOT NULL,
                    api_key     TEXT,
                    status      TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    customer_id TEXT,
                    subscription_id TEXT
                );
            """)
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS usage (
                    api_key TEXT NOT NULL,
                    period  TEXT NOT NULL,
                    count   INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (api_key, period)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    api_key TEXT PRIMARY KEY,
                    plan TEXT NOT NULL,
                    monthly_limit INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    session_id  TEXT PRIMARY KEY,
                    email       TEXT,
                    plan        TEXT NOT NULL,
                    api_key     TEXT,
                    status      TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    customer_id TEXT,
                    subscription_id TEXT
                )
            """)
            con.commit()
        # SQLite: add columns if missing
        try:
            with db_conn() as con:
                cur = con.cursor()
                for col in ("customer_id","subscription_id"):
                    try:
                        cur.execute(f"ALTER TABLE orders ADD COLUMN {col} TEXT")
                        con.commit()
                    except Exception:
                        pass
        except Exception:
            pass

def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")

# ----- Keys (DB or file) -----
def keys_db_get(api_key: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT plan, monthly_limit, created_at FROM keys WHERE api_key = %s" if DB_IS_PG else \
            "SELECT plan, monthly_limit, created_at FROM keys WHERE api_key = ?"
        cur.execute(q, (api_key,))
        row = cur.fetchone()
        if not row:
            return None
        plan, monthly_limit, created_at = row
        return {"plan": plan, "monthly_limit": int(monthly_limit), "created_at": created_at}

def keys_db_insert(api_key: str, plan: str, monthly_limit: int):
    with db_conn() as con:
        cur = con.cursor()
        q = "INSERT INTO keys(api_key, plan, monthly_limit, created_at) VALUES (%s,%s,%s,%s)" if DB_IS_PG else \
            "INSERT INTO keys(api_key, plan, monthly_limit, created_at) VALUES (?,?,?,?)"
        cur.execute(q, (api_key, plan, int(monthly_limit), datetime.datetime.utcnow().isoformat()+"Z"))
        con.commit()

def keys_db_update(api_key: str, plan: Optional[str] = None, monthly_limit: Optional[int] = None):
    if plan is None and monthly_limit is None:
        return
    with db_conn() as con:
        cur = con.cursor()
        if plan is not None and monthly_limit is not None:
            q = "UPDATE keys SET plan=%s, monthly_limit=%s WHERE api_key=%s" if DB_IS_PG else \
                "UPDATE keys SET plan=?, monthly_limit=? WHERE api_key=?"
            cur.execute(q, (plan, int(monthly_limit), api_key))
        elif plan is not None:
            q = "UPDATE keys SET plan=%s WHERE api_key=%s" if DB_IS_PG else \
                "UPDATE keys SET plan=? WHERE api_key=?"
            cur.execute(q, (plan, api_key))
        else:
            q = "UPDATE keys SET monthly_limit=%s WHERE api_key=%s" if DB_IS_PG else \
                "UPDATE keys SET monthly_limit=? WHERE api_key=?"
            cur.execute(q, (int(monthly_limit), api_key))
        con.commit()

def keys_db_delete(api_key: str):
    with db_conn() as con:
        cur = con.cursor()
        q = "DELETE FROM keys WHERE api_key=%s" if DB_IS_PG else "DELETE FROM keys WHERE api_key=?"
        cur.execute(q, (api_key,))
        con.commit()

def keys_db_list(limit: int = 1000) -> List[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT api_key, plan, monthly_limit, created_at FROM keys ORDER BY created_at DESC LIMIT %s" if DB_IS_PG else \
            "SELECT api_key, plan, monthly_limit, created_at FROM keys ORDER BY created_at DESC LIMIT ?"
        cur.execute(q, (limit,))
        rows = cur.fetchall()
        return [{"api_key": r[0], "plan": r[1], "monthly_limit": int(r[2]), "created_at": r[3]} for r in rows]

def load_keys_file() -> Dict[str, Dict]:
    if not os.path.exists(KEYS_PATH):
        return {}
    with open(KEYS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_keys_file(keys: Dict[str, Dict]):
    with open(KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

def issue_key(plan: str, limit_override: Optional[int] = None) -> str:
    plan = plan.lower()
    if plan not in PLANS:
        plan = "free"
    while True:
        k = uuid.uuid4().hex.upper()
        if KEYS_BACKEND == "db":
            if not keys_db_get(k):
                break
        else:
            keys = load_keys_file()
            if k not in keys:
                break
    monthly_limit = int(limit_override or PLANS[plan]["monthly_limit"])
    if KEYS_BACKEND == "db":
        keys_db_insert(k, plan, monthly_limit)
    else:
        keys = load_keys_file()
        keys[k] = {"plan": plan, "monthly_limit": monthly_limit}
        save_keys_file(keys)
    return k

def get_limit_for_key(api_key: str) -> int:
    """
    Return the effective monthly limit for a key without mutating storage.
    We compute max(stored_limit, plan_default) and DO NOT write to DB/file here.
    """
    if not api_key:
        return -1

    def plan_default(plan: str) -> int:
        p = (plan or "free").lower()
        return int(PLANS.get(p, PLANS["free"])["monthly_limit"])

    if KEYS_BACKEND == "db":
        meta = keys_db_get(api_key)
        if not meta:
            return -1
        stored = int(meta.get("monthly_limit") or 0)
        return max(stored, plan_default(meta.get("plan")))
    else:
        keys = load_keys_file()
        meta = keys.get(api_key)
        if not meta:
            return -1
        stored = int(meta.get("monthly_limit") or 0)
        return max(stored, plan_default(meta.get("plan")))

def get_plan_for_key(api_key: str) -> Optional[str]:
    if KEYS_BACKEND == "db":
        meta = keys_db_get(api_key)
        return (meta or {}).get("plan")
    else:
        meta = load_keys_file().get(api_key)
        return (meta or {}).get("plan")

# ----- Usage counters -----
def get_usage(api_key: str, period: Optional[str] = None) -> int:
    period = period or current_period()
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT count FROM usage WHERE api_key=%s AND period=%s" if DB_IS_PG else \
            "SELECT count FROM usage WHERE api_key=? AND period=?"
        cur.execute(q, (api_key, period))
        row = cur.fetchone()
        return int(row[0]) if row else 0

def increment_usage(api_key: str, amount: int = 1) -> int:
    period = current_period()
    with db_conn() as con:
        cur = con.cursor()
        if DB_IS_PG:
            cur.execute("""
                INSERT INTO usage(api_key, period, count)
                VALUES (%s, %s, 0)
                ON CONFLICT (api_key, period) DO NOTHING
            """, (api_key, period))
            cur.execute("UPDATE usage SET count = count + %s WHERE api_key=%s AND period=%s", (amount, api_key, period))
            cur.execute("SELECT count FROM usage WHERE api_key=%s AND period=%s", (api_key, period))
        else:
            cur.execute("INSERT OR IGNORE INTO usage(api_key, period, count) VALUES(?, ?, 0)", (api_key, period))
            cur.execute("UPDATE usage SET count = count + ? WHERE api_key=? AND period=?", (amount, api_key, period))
            cur.execute("SELECT count FROM usage WHERE api_key=? AND period=?", (api_key, period))
        row = cur.fetchone()
        con.commit()
        return int(row[0]) if row else 0

# ---------- Filtering / sorting ----------
_num_clean_re = re.compile(r"[,\s]")
_filter_re = re.compile(r"""^\s*(?P<col>[^:~^\$><=!]+?)\s*(?P<op>>=|<=|!=|>|<|~|\^|\$|:)\s*(?P<val>.+?)\s*$""")

def _to_number(s: Optional[str]) -> Optional[float]:
    if s is None:
        return None
    t = str(s).strip()
    if not t:
        return None
    if t.startswith("$"): t = t[1:]
    pct = t.endswith("%")
    if pct: t = t[:-1]
    t = _num_clean_re.sub("", t)
    try:
        v = float(t)
        return v/100.0 if pct else v
    except Exception:
        return None

def _match_filter(row_val: Optional[str], op: str, val: str) -> bool:
    if op in (":", "!=", "~", "^", "$"):
        a = (row_val or "").strip().lower(); b = val.strip().lower()
        return {":": a == b, "!=": a != b, "~": b in a, "^": a.startswith(b), "$": a.endswith(b)}[op]
    if op in (">", "<", ">=", "<="):
        x = _to_number(row_val); y = _to_number(val)
        if x is None or y is None: return False
        return {">": x>y, "<": x<y, ">=": x>=y, "<=": x<=y}[op]
    return False

def _parse_order(order: Optional[str]) -> Tuple[Optional[str], bool, bool]:
    if not order: return None, False, False
    reverse = order.startswith("-")
    core = order[1:] if reverse else order
    numeric = core.endswith(":num")
    if numeric: core = core[:-4]
    return core, reverse, numeric

# ---------- Safety: validate CSV URL ----------
def validate_csv_url(csv_url: str):
    try:
        u = urlparse(csv_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid csv_url")
    if u.scheme != "https":
        raise HTTPException(status_code=400, detail="csv_url must be https")

    # Allow our own demo CSV endpoints
    if PUBLIC_HOST and u.netloc == PUBLIC_HOST and u.path.startswith("/demo/csv/"):
        return

    # Only allow published Google Sheets CSV
    if not (u.netloc.endswith("docs.google.com")):
        raise HTTPException(status_code=400, detail="Only Google Sheets 'Publish to web → CSV' links are allowed")
    if "/pub" not in u.path:
        raise HTTPException(status_code=400, detail="csv_url must be a published CSV (path should contain /pub)")
    qs = parse_qs(u.query)
    if "output" not in qs or "csv" not in [v.lower() for v in qs["output"]]:
        raise HTTPException(status_code=400, detail="csv_url must include output=csv")

# ---------- CSV fetch ----------
def fetch_csv_rows(csv_url: str, bypass_cache: bool = False) -> Tuple[List[Dict[str, str]], str]:
    now = time.time()
    if not bypass_cache:
        ent = _cache.get(csv_url)
        if ent and (now - ent["ts"] < CACHE_TTL):
            return ent["rows"], ent["raw_sha"]

    try:
        r = requests.get(csv_url, timeout=12)
        r.raise_for_status()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"CSV fetch failed: {e}")

    max_bytes = 5_000_000
    cl = r.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > max_bytes:
        raise HTTPException(status_code=413, detail="CSV too large (>5MB)")
    content_bytes = r.content
    if len(content_bytes) > max_bytes:
        raise HTTPException(status_code=413, detail="CSV too large (>5MB)")

    content_text = content_bytes.decode("utf-8", errors="replace")
    try:
        sample = content_text[:2048]
        dialect = csv.Sniffer().sniff(sample, delimiters=[",",";","\t","|"])
        delim = dialect.delimiter
    except Exception:
        delim = ","

    reader = csv.DictReader(io.StringIO(content_text), delimiter=delim)
    rows = [dict(row) for row in reader]

    raw_sha = hashlib.sha1(content_bytes).hexdigest()
    _cache[csv_url] = {"ts": now, "rows": rows, "raw_sha": raw_sha}
    return rows, raw_sha

# ---------- Transform ----------
def apply_filters(rows, select=None, filters=None, order=None, limit=None, offset=None):
    out = rows
    if filters:
        for f in filters:
            m = _filter_re.match(f)
            if not m: continue
            col, op, val = m.group("col").strip(), m.group("op"), m.group("val")
            out = [r for r in out if (col in r and _match_filter(r.get(col), op, val))]
    if select:
        cols = [c.strip() for c in select.split(",") if c.strip()]
        out = [{k: v for k, v in r.items() if k in cols} for r in out]
    if order:
        key, reverse, numeric = _parse_order(order)
        if key:
            if numeric:
                out.sort(key=lambda r: (_to_number(r.get(key)) if _to_number(r.get(key)) is not None else float("-inf")), reverse=reverse)
            else:
                out.sort(key=lambda r: (r.get(key) or ""), reverse=reverse)
    start = int(offset or 0)
    end = start + int(limit) if limit else None
    out = out[start:end]
    return out

# ---------- API key enforcement & rate limiting ----------
def require_and_track_key(api_key_header: Optional[str], api_key_query: Optional[str]):
    if not REQUIRE_API_KEY:
        return None
    api_key = api_key_header or api_key_query
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Use header 'x-api-key' or query ?key=...")
    limit = get_limit_for_key(api_key)
    if limit <= 0:
        raise HTTPException(status_code=401, detail="Invalid API key")
    used = get_usage(api_key)
    if used >= limit:
        raise HTTPException(status_code=429, detail=f"Monthly limit reached ({used}/{limit}). Upgrade your plan.")
    used_after = increment_usage(api_key, 1)
    if used_after > limit:
        raise HTTPException(status_code=429, detail=f"Monthly limit reached ({used_after}/{limit}). Upgrade your plan.")
    return api_key

def rate_limit_ok(bucket: str) -> bool:
    now = time.time(); window = 60.0; lim = RATE_LIMIT_PER_MIN
    arr = _rl.get(bucket, [])
    arr = [t for t in arr if now - t < window]
    if len(arr) >= lim:
        _rl[bucket] = arr; return False
    arr.append(now); _rl[bucket] = arr; return True

def rl_or_429(request: Request, api_key: Optional[str]):
    ident = api_key or (request.client.host if request.client else "unknown")
    if not rate_limit_ok(ident):
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")

# ---------- Logo / Favicon ----------
LOGO_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
  <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#6ea8fe'/><stop offset='100%' stop-color='#7bd3ff'/></linearGradient></defs>
  <rect x='16' y='16' width='224' height='224' rx='48' fill='#0e1630'/>
  <rect x='24' y='24' width='208' height='208' rx='40' fill='url(#g)' opacity='0.08'/>
  <g fill='#eaf0ff'>
    <text x='50%' y='46%' text-anchor='middle' font-size='88' font-family='ui-sans-serif, system-ui, Segoe UI, Roboto' font-weight='800'>{ }</text>
    <text x='50%' y='72%' text-anchor='middle' font-size='78' font-family='ui-sans-serif, system-ui, Segoe UI, Roboto' font-weight='900'>S</text>
  </g>
</svg>"""

@app.get("/logo.svg")
def logo_svg():
    return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

@app.get("/favicon.svg")
def favicon_svg():
    return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

# ---------- Shared HTML head ----------
def _html_head(title: str) -> str:
    return (
        '<meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />'
        + _google_verify_snippet()
        + "<title>" + title + "</title><link rel=\"icon\" href=\"/favicon.svg\">"
        + _analytics_snippet()
        + """
<style>
  :root{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#6ea8fe;}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}
  .wrap{max-width:960px;margin:40px auto;padding:0 16px}
  .card{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}
  h1{margin:0 0 6px;font-size:28px} p{margin:0 0 16px;color:var(--muted)}
  header{display:flex;align-items:center;gap:12px;margin-bottom:14px}
  header img{width:36px;height:36px}
  nav a{color:#9cc2ff;margin-right:14px;text-decoration:none} nav a:hover{text-decoration:underline}
  label{display:block;margin:12px 0 6px;color:#c8d1f5}
  input,textarea,button,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}
  textarea{min-height:64px}
  button{background:var(--accent);border:none;color:#04122d;font-weight:700;cursor:pointer}
  .grid{display:grid;gap:12px} @media(min-width:820px){.grid{grid-template-columns:1.5fr 1fr}}
  pre{background:#0a0f24;border:1px solid #26335f;border-radius:12px;padding:14px;overflow:auto}
  small{color:var(--muted)} .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .hint{font-size:13px;color:#aab8e6} .pill{display:inline-block;background:#0a1638;border:1px solid #24336a;border-radius:99px;padding:4px 8px;margin-right:6px;color:#a9b8ee}
  a{color:#9cc2ff} #status{margin:8px 0 0 0;font-size:13px;color:#aab8e6} code{background:#0a0f24;border:1px solid #26335f;border-radius:6px;padding:0 4px}
  .pricegrid{display:grid;gap:12px} @media(min-width:720px){.pricegrid{grid-template-columns:repeat(3,1fr)}}
  .plan{background:#0e1630;border:1px solid #233366;border-radius:14px;padding:16px}
  .plan h3{margin:0 0 6px} .cta{margin-top:8px}
  table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #233366;text-align:left}
  .btn{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:#eaf0ff;text-decoration:none}
  .cards{display:grid;gap:12px} @media(min-width:820px){.cards{grid-template-columns:repeat(3,1fr)}}
</style>"""
    )

# ---------- Embed generator page ----------
@app.get("/embed", response_class=HTMLResponse, tags=["Pages"])
def embed_generator():
    head = _html_head("SheetsJSON — Embed Generator")
    return HTMLResponse(
        "<!doctype html><html><head>"+head+"</head><body><div class='wrap'>"
        "<header><img src='/logo.svg' alt='SheetsJSON logo' style='width:36px;height:36px;margin-right:8px'/>"
        "<strong>SheetsJSON</strong></header>"
        "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a>"
        "<a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a><a href='/embed'>Embed</a></nav>"
        "<div class='card'><h1>Embed a Google Sheet as a table</h1>"
        "<p>Publish your Sheet to CSV, then paste the URL and options. Copy the snippet into Webflow/Framer/any site.</p>"
        "<label>Published CSV URL</label><input id='csv' placeholder='https://docs.google.com/.../pub?output=csv'/>"
        "<div class='row'><div><label>API key</label><input id='key' placeholder='YOUR_API_KEY'/></div>"
        "<div><label>Page size</label><input id='page' type='number' value='10'/></div></div>"
        "<div class='row'><div><label>Select columns (comma)</label><input id='select' placeholder='name,price,status'/></div>"
        "<div><label>Default order</label><input id='order' placeholder='-price:num'/></div></div>"
        "<label>Filters (separate multiple with ;)</label><input id='filters' placeholder='status:active;price<20'/>"
        "<div class='row'><div><label>Theme</label><select id='theme'><option>auto</option><option>light</option><option>dark</option></select></div>"
        "<div><label>Max rows to fetch</label><input id='limit' type='number' value='500'/></div></div>"
        "<div style='margin-top:8px'><button id='gen' type='button'>Generate snippet</button></div>"
        "</div>"
        "<div class='card' style='margin-top:14px'><h2>Snippet</h2><pre id='out'>&lt;!-- fill the form and click Generate --&gt;</pre></div>"
        "</div><script>"
        "const $=id=>document.getElementById(id);"
        "document.getElementById('gen').addEventListener('click',()=>{"
        " const csv=$('csv').value.trim(); const key=$('key').value.trim();"
        " if(!csv){$('out').textContent='// Add a CSV URL first'; return;}"
        " const attrs=[];"
        " attrs.push(`data-csv=\"${csv.replace(/\"/g,'&quot;')}\"`);"
        " if(key) attrs.push(`data-key=\"${key.replace(/\"/g,'&quot;')}\"`);"
        " const sel=$('select').value.trim(); if(sel) attrs.push(`data-select=\"${sel}\"`);"
        " const ord=$('order').value.trim(); if(ord) attrs.push(`data-order=\"${ord}\"`);"
        " const fil=$('filters').value.trim(); if(fil) attrs.push(`data-filters=\"${fil}\"`);"
        " const page=$('page').value.trim(); if(page) attrs.push(`data-page=\"${page}\"`);"
        " const limit=$('limit').value.trim(); if(limit) attrs.push(`data-limit=\"${limit}\"`);"
        " const theme=$('theme').value.trim(); if(theme) attrs.push(`data-theme=\"${theme}\"`);"
        " const div = `<div class=\"sj-table\" ${attrs.join(' ')}></div>`;"
        " const scr = `<script src=\""+(PUBLIC_BASE_URL or '')+"/embed.js\" async></`+\"script>`;"
        " $('out').textContent = div + '\\n' + scr;"
        "});"
        "</script></body></html>"
    )

# ---------- Embeddable JS (renders a searchable/sortable table) ----------
@app.get("/embed.js", tags=["Pages"])
def embed_js():
    js = r"""
(function(){
  'use strict';

  // Ready helper
  function onReady(fn){ if(document.readyState!=='loading'){fn()} else {document.addEventListener('DOMContentLoaded', fn);} }

  // Escape HTML
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;' }[m])); }

  // Parse numbers for sorting
  function toNum(v){
    if (v == null) return null;
    let t = String(v).trim();
    if (!t) return null;
    if (t[0] === '$') t = t.slice(1);
    const pct = t.endsWith('%');
    if (pct) t = t.slice(0, -1);
    t = t.replace(/[, \t]/g,'');
    const n = parseFloat(t);
    if (!isFinite(n)) return null;
    return pct ? n/100 : n;
  }

  // Style injection (scoped by classes)
  function ensureStyles(){
    if (document.getElementById('sj-embed-css')) return;
    const css = `
.sj-wrap{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto;color:#eaf0ff}
.sj-theme-light .sj-wrap{color:#0c1633}
.sj-box{background:#0e1630;border:1px solid #233366;border-radius:12px;padding:10px;overflow:auto}
.sj-theme-light .sj-box{background:#f7f9ff;border-color:#d6e0ff}
.sj-controls{display:flex;gap:8px;align-items:center;margin:6px 0 10px}
.sj-search{flex:1 1 auto;padding:8px 10px;border-radius:8px;border:1px solid #26335f;background:#0a0f24;color:inherit}
.sj-theme-light .sj-search{background:#fff;border-color:#ccd6ff}
.sj-select{padding:6px 10px;border-radius:8px;border:1px solid #26335f;background:#0a0f24;color:inherit}
.sj-theme-light .sj-select{background:#fff;border-color:#ccd6ff}
.sj-table-el{width:100%;border-collapse:collapse}
.sj-th,.sj-td{padding:8px 10px;border-bottom:1px solid #233366;text-align:left;vertical-align:top}
.sj-theme-light .sj-th,.sj-theme-light .sj-td{border-bottom-color:#dbe4ff}
.sj-th{user-select:none;cursor:pointer;white-space:nowrap}
.sj-sort{opacity:.7;margin-left:6px;font-size:11px}
.sj-pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:8px}
.sj-btn{padding:6px 10px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:inherit;cursor:pointer}
.sj-theme-light .sj-btn{background:#f7f9ff;border-color:#d6e0ff}
.sj-btn[disabled]{opacity:.5;cursor:not-allowed}
.sj-small{font-size:12px;opacity:.8}
.sj-loading,.sj-error{padding:8px 10px}
`;
    const el = document.createElement('style'); el.id='sj-embed-css'; el.textContent=css; document.head.appendChild(el);
  }

  // Find script origin for API base
  function scriptOrigin(){
    const cand = document.currentScript || document.querySelector('script[src*="/embed.js"]');
    try { return cand ? (new URL(cand.src)).origin : window.location.origin; } catch(e){ return window.location.origin; }
  }

  // Build table component inside a container with data-* attributes
  function initContainer(container){
    const d = container.dataset;
    const csv = (d.csv||'').trim();
    if(!csv){ container.innerHTML = "<div class='sj-error'>Missing <code>data-csv</code></div>"; return; }
    const key = (d.key||'').trim();
    const select = (d.select||'').trim();
    const order = (d.order||'').trim();
    const filters = (d.filters||'').trim(); // separate multiple with ';'
    const pageSize = Math.max(1, parseInt(d.page||'10',10));
    const limit = Math.max(pageSize, parseInt(d.limit||'500',10)); // max rows to fetch
    const theme = (d.theme||'auto');

    // UI shell
    ensureStyles();
    const wrap = document.createElement('div');
    wrap.className = 'sj-wrap ' + (theme==='dark'?'sj-theme-dark':(theme==='light'?'sj-theme-light':(matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? 'sj-theme-dark':'sj-theme-light')));
    const box = document.createElement('div'); box.className='sj-box';
    const controls = document.createElement('div'); controls.className='sj-controls';
    const search = document.createElement('input'); search.className='sj-search'; search.placeholder='Search…'; search.setAttribute('aria-label','Search');
    controls.appendChild(search);
    const table = document.createElement('table'); table.className='sj-table-el';
    const thead = document.createElement('thead'); const tbody = document.createElement('tbody');
    table.appendChild(thead); table.appendChild(tbody);
    const pager = document.createElement('div'); pager.className='sj-pager';
    const prev = document.createElement('button'); prev.className='sj-btn'; prev.textContent='Prev';
    const next = document.createElement('button'); next.className='sj-btn'; next.textContent='Next';
    const info = document.createElement('span'); info.className='sj-small';
    pager.appendChild(prev); pager.appendChild(next); pager.appendChild(info);
    box.appendChild(controls); box.appendChild(table); box.appendChild(pager);
    container.innerHTML=''; container.appendChild(wrap); wrap.appendChild(box);

    // State
    let rows = []; let view = []; let cols = []; let sortCol = null; let sortDir = 1; let sortNumeric = false;
    let page = 1;

    function setInfo(){
      const total = view.length; const pages = Math.max(1, Math.ceil(total / pageSize));
      if(page>pages) page = pages;
      info.textContent = total ? ("Page "+page+" / "+pages+" • "+total+" rows") : "No rows";
      prev.disabled = (page<=1); next.disabled = (page>=pages);
    }

    function detectNumeric(col){
      for(const r of view){ const v = toNum(r[col]); if(v!=null) return true; }
      return false;
    }

    function renderHead(){
      const tr = document.createElement('tr');
      cols.forEach(c=>{
        const th = document.createElement('th'); th.className='sj-th'; th.textContent=c;
        const s = document.createElement('span'); s.className='sj-sort'; s.textContent = c===sortCol ? (sortDir>0?'▲':'▼') : '↕';
        th.appendChild(s);
        th.addEventListener('click', ()=>{
          if(sortCol===c){ sortDir = -sortDir; } else { sortCol=c; sortDir=1; sortNumeric = detectNumeric(c); }
          sortView(); renderBody(); renderHead();
        });
        tr.appendChild(th);
      });
      thead.innerHTML=''; thead.appendChild(tr);
    }

    function rowMatchesSearch(r, q){
      if(!q) return true;
      const needle = q.toLowerCase();
      for(const c of cols){
        const v = (r[c]==null?'':String(r[c])).toLowerCase();
        if(v.includes(needle)) return true;
      }
      return false;
    }

    function sortView(){
      if(!sortCol) return;
      view.sort((a,b)=>{
        const A = a[sortCol], B = b[sortCol];
        if(sortNumeric){
          const x = toNum(A), y = toNum(B);
          if(x==null && y==null) return 0;
          if(x==null) return -1*sortDir;
          if(y==null) return 1*sortDir;
          return (x<y?-1:(x>y?1:0))*sortDir;
        } else {
          const x = (A==null?'':String(A)).toLowerCase();
          const y = (B==null?'':String(B)).toLowerCase();
          return (x<y?-1:(x>y?1:0))*sortDir;
        }
      });
    }

    function renderBody(){
      const total = view.length; const pages = Math.max(1, Math.ceil(total / pageSize));
      if(page>pages) page = pages;
      const start = (page-1)*pageSize, end = Math.min(start+pageSize, total);
      const frag = document.createDocumentFragment();
      for(let i=start;i<end;i++){
        const r = view[i]; const tr = document.createElement('tr');
        cols.forEach(c=>{ const td=document.createElement('td'); td.className='sj-td'; td.innerHTML=esc(r[c]??''); tr.appendChild(td); });
        frag.appendChild(tr);
      }
      tbody.innerHTML=''; tbody.appendChild(frag);
      setInfo();
    }

    // Wire events
    search.addEventListener('input', ()=>{
      const q = search.value.trim();
      view = rows.filter(r=>rowMatchesSearch(r,q));
      sortView(); page = 1; renderBody();
    });
    prev.addEventListener('click', ()=>{ if(page>1){ page--; renderBody(); } });
    next.addEventListener('click', ()=>{ const pages=Math.max(1,Math.ceil(view.length/pageSize)); if(page<pages){ page++; renderBody(); } });

    // Fetch data
    (async function(){
      const base = scriptOrigin();
      const u = new URL(base + "/v1/fetch");
      u.searchParams.set("csv_url", csv);
      if (select) u.searchParams.set("select", select);
      if (order) u.searchParams.set("order", order);
      if (limit) u.searchParams.set("limit", String(limit));
      if (filters){
        filters.split(';').map(s=>s.trim()).filter(Boolean).forEach(f=>u.searchParams.append("filter", f));
      }
      // Loading state
      container.querySelector('.sj-box').insertAdjacentHTML('afterbegin', "<div class='sj-loading'>Loading…</div>");
      const loadingEl = container.querySelector('.sj-loading');
      try{
        const headers = key ? {"x-api-key": key} : {};
        const res = await fetch(u.toString(), { headers });
        const text = await res.text();
        if(!res.ok){ throw new Error("HTTP "+res.status+" "+text); }
        let data; try{ data = JSON.parse(text); } catch{ data = { rows: [] }; }
        rows = (data && (data.rows || data.data)) || [];
        // Columns
        if (select){
          cols = select.split(',').map(s=>s.trim()).filter(Boolean);
        } else {
          cols = rows.length ? Object.keys(rows[0]) : [];
        }
        // Default sort from 'order' (e.g., -price:num)
        if(order){
          let o = order.trim(); sortDir = 1; if(o.startsWith('-')){ sortDir=-1; o=o.slice(1); }
          if(o.endsWith(':num')){ sortNumeric=true; o=o.slice(0,-4); } else { sortNumeric=false; }
          sortCol = o;
        }
        view = rows.slice(0);
        sortView(); renderHead(); renderBody();
      }catch(e){
        container.innerHTML = "<div class='sj-error'>"+esc(e.message||String(e))+"</div>";
      } finally {
        if (loadingEl && loadingEl.remove) loadingEl.remove();
      }
    })();
  }

  onReady(function(){
    document.querySelectorAll('.sj-table,[data-csv]').forEach(initContainer);
  });
})();
"""
    return FastAPIResponse(content=js, media_type="application/javascript")

# ---------- Pages ----------
def _home_html() -> str:
    return (
        "<!doctype html><html lang='en'><head>"
        + _html_head("SheetsJSON — CSV → JSON API")
        + "</head><body><div class='wrap'>"
        + "<header><img src='/logo.svg' alt='SheetsJSON logo'/>"
        + "<div><strong>SheetsJSON</strong><br/><small class='hint'>Google Sheets → JSON API</small></div></header>"
        + "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a><a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
        + "<div class='card'><h1>Try it now</h1><p>Paste a Google Sheets <strong>Publish to web → CSV</strong> link (or click an example), add your API key, and press Fetch.</p>"
        + "<div class='grid'><div>"
        + "<label>Google Sheets CSV URL</label><input id='csv' placeholder='https://docs.google.com/.../pub?output=csv'/>"
        + "<label>API key <small class='hint'>(header <code>x-api-key</code> or <code>?key=</code>)</small></label><input id='key' placeholder='FREE_EXAMPLE_KEY_123'/>"
        + "<div class='row'><div><label><span class='pill'>optional</span> select</label><input id='select' placeholder='name,email'/></div>"
        + "<div><label><span class='pill'>optional</span> order <small class='hint'>(e.g., <code>price:num</code>, <code>-age:num</code>, or <code>name</code>)</small></label><input id='order' placeholder='price:num'/></div></div>"
        + "<div class='row'><div><label><span class='pill'>optional</span> limit</label><input id='limit' type='number' placeholder='50'/></div>"
        + "<div><label><span class='pill'>optional</span> offset</label><input id='offset' type='number' placeholder='0'/></div></div>"
        + "<label><span class='pill'>optional</span> filters (one per line)</label>"
        + "<textarea id='filters' placeholder='status:active&#10;name~ali&#10;age&gt;=21&#10;price&lt;100'></textarea>"
        + "<small class='hint'>Supported: <code>col:value</code>, <code>col!=v</code>, <code>col~v</code>, <code>col^v</code>, <code>col$v</code>, numeric <code>col&gt;=num</code>/<code>&lt;=</code>/<code>&gt;</code>/<code>&lt;</code>. Add <code>cache_bypass=1</code> in query to refetch.</small>"
        + "<div class='row' style='margin-top:8px'><button id='go' type='button' onclick='window.plausible && plausible(\"FetchClicked\")'>Fetch JSON</button><button id='usage' type='button'>Check Usage</button></div>"
        + "<div id='status'>Ready.</div><small class='hint'>Need a key? <a href='/request-key'>Request one</a>. See <a href='/examples'>Examples</a>.</small></div>"
        + "<div><label>Result</label><pre id='out'>Waiting…</pre><label>Curl</label><pre id='curl'># will appear after a request</pre><label>ETag</label><pre id='etag'># returns entity tag for caching</pre></div>"
        + "</div></div>"
        + "<p class='hint'>By using SheetsJSON you agree to our <a href='/terms'>Terms</a> and acknowledge our <a href='/privacy'>Privacy Policy</a>.</p>"
        + "</div>"
        + "<script>"
        + "const $=(id)=>document.getElementById(id);"
        + "function buildURL(){const u=new URL(window.location.origin+\"/v1/fetch\");"
        + "const filters=$(\"filters\").value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);"
        + "const csv=$(\"csv\").value.trim(); if(csv) u.searchParams.set(\"csv_url\",csv);"
        + "const sel=$(\"select\").value.trim(); if(sel) u.searchParams.set(\"select\",sel);"
        + "const ord=$(\"order\").value.trim(); if(ord) u.searchParams.set(\"order\",ord);"
        + "const lim=$(\"limit\").value.trim(); if(lim) u.searchParams.set(\"limit\",lim);"
        + "const off=$(\"offset\").value.trim(); if(off) u.searchParams.set(\"offset\",off);"
        + "filters.forEach(f=>u.searchParams.append(\"filter\",f)); return u;}"
        + "async function runFetch(){"
        + "$(\"status\").textContent='Loading…'; const key=$(\"key\").value.trim(); const url=buildURL();"
        + "try{const res=await fetch(url, key?{headers:{\"x-api-key\":key}}:undefined);"
        + "$(\"status\").textContent='HTTP '+res.status; const text=await res.text();"
        + "const etag=res.headers.get('etag'); $(\"etag\").textContent=etag?etag:'(none)';"
        + "try{$(\"out\").textContent=JSON.stringify(JSON.parse(text),null,2);}catch{$(\"out\").textContent=text;}"
        + "const curl=['curl', key?'-H \\\"x-api-key: '+key.replace(/\"/g,'\\\\\\\"')+'\\\"':'', etag?'-H \\\"If-None-Match: '+etag+'\\\"':'', '\"'+url.toString().replace(/\"/g,'\\\"')+'\"'].filter(Boolean).join(' ');"
        + "$(\"curl\").textContent=curl;"
        + "}catch(e){$(\"status\").textContent='Error'; $(\"out\").textContent='Error: '+e; console.error(e);}}"
        + "async function runUsage(){$(\"status\").textContent='Loading usage…'; const key=$(\"key\").value.trim(); if(!key){$(\"out\").textContent='Add your API key first.'; $(\"status\").textContent='Ready.'; return;} "
        + "try{const res=await fetch('/v1/usage',{headers:{'x-api-key':key}}); $(\"status\").textContent='HTTP '+res.status; const text=await res.text(); try{$(\"out\").textContent=JSON.stringify(JSON.parse(text),null,2);}catch{$(\"out\").textContent=text;}}catch(e){$(\"status\").textContent='Error'; $(\"out\").textContent='Error: '+e;}}"
        + "function prefillFromQuery(){const q=new URLSearchParams(location.search); const map=[['csv','csv'],['key','key'],['select','select'],['order','order'],['limit','limit'],['offset','offset']]; map.forEach(([qs,id])=>{const v=q.get(qs); if(v!==null) $(id).value=v;}); const filters=q.getAll('filter'); if(filters.length) $(\"filters\").value=filters.join('\\n'); if(q.get('autorun')==='1') runFetch();}"
        + "document.getElementById('go').addEventListener('click',runFetch); document.getElementById('usage').addEventListener('click',runUsage); prefillFromQuery();"
        + "</script></body></html>"
    )

def fmt_price(n: int) -> str:
    return "$0" if n == 0 else f"${n}/mo"

def _pricing_html() -> str:
    sub_on = SUBSCRIBE_ENABLED
    pro_button = (
        "<form method='post' action='/billing/checkout' onsubmit=\"window.plausible && plausible('CheckoutStart', {props:{plan:'pro'}})\">"
        "<input type='hidden' name='plan' value='pro'/><button class='btn' type='submit'>Subscribe</button></form>"
        if sub_on else "<div class='hint'>Stripe not configured</div>"
    )
    plus_button = (
        "<form method='post' action='/billing/checkout' onsubmit=\"window.plausible && plausible('CheckoutStart', {props:{plan:'plus'}})\">"
        "<input type='hidden' name='plan' value='plus'/><button class='btn' type='submit'>Subscribe</button></form>"
        if sub_on else "<div class='hint'>Stripe not configured</div>"
    )
    return (
        "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — Pricing & Docs")+"</head>"
        "<body><div class='wrap'>"
        "<header><img src='/logo.svg' alt='SheetsJSON logo' style='width:36px;height:36px;margin-right:8px'/><strong>SheetsJSON</strong></header>"
        "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a><a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
        "<div class='card'><h1>Pricing</h1>"
        "<div class='pricegrid'>"
        "<div class='plan'><h3>"+PLANS['free']['label']+"</h3>"
        "<p><strong>"+fmt_price(PLANS['free']['price'])+"</strong></p>"
        "<ul><li>"+str(PLANS['free']['monthly_limit'])+" requests / month</li><li>5-minute server cache</li><li>Filters & sorting</li></ul>"
        "<div class='cta'><a class='hint' href='/request-key'>Get a Free key →</a></div></div>"
        "<div class='plan'><h3>"+PLANS['pro']['label']+"</h3>"
        "<p><strong>"+fmt_price(PLANS['pro']['price'])+"</strong></p>"
        "<ul><li>"+str(PLANS['pro']['monthly_limit'])+" requests / month</li><li>Priority cache & support</li><li>ETag / client caching</li></ul>"
        + pro_button +
        "</div>"
        "<div class='plan'><h3>"+PLANS['plus']['label']+"</h3>"
        "<p><strong>"+fmt_price(PLANS['plus']['price'])+"</strong></p>"
        "<ul><li>"+str(PLANS['plus']['monthly_limit'])+" requests / month</li><li>Higher limits on demand</li><li>Team usage reporting</li></ul>"
        + plus_button +
        "</div>"
        "</div></div>"
        "<div class='card' style='margin-top:14px'><h1>Quick Docs</h1>"
        "<p><strong>Endpoint:</strong> <code>GET /v1/fetch</code></p>"
        "<p><strong>Header:</strong> <code>x-api-key: YOUR_KEY</code> (or <code>?key=YOUR_KEY</code>)</p>"
        "<p><strong>Required:</strong> <code>csv_url</code> → Google Sheets <em>Publish to web → CSV</em> link</p>"
        "<ul>"
        "<li><code>select</code>: e.g., <code>name,email</code></li>"
        "<li><code>filter</code> (repeatable): <code>col:value</code>, <code>col!=v</code>, <code>col~v</code>, <code>col^v</code>, <code>col$v</code>, numeric <code>col&gt;=num</code>/<code>&lt;=</code>/<code>&gt;</code>/<code>&lt;</code></li>"
        "<li><code>order</code>: string <code>col</code> or numeric <code>col:num</code> (desc with <code>-</code>)</li>"
        "<li><code>limit</code>, <code>offset</code>; <code>cache_bypass=1</code> to refetch</li>"
        "</ul>"
        "<h3>Quick examples</h3>"
        "<pre>curl -H \"x-api-key: YOUR_KEY\" \""+PUBLIC_BASE_URL+"/v1/fetch?csv_url=...&filter=status:active&order=-price:num&limit=50\"</pre>"
        "<pre>// Node\n// npm i node-fetch\nimport fetch from 'node-fetch';\nconst res = await fetch('"+PUBLIC_BASE_URL+"/v1/fetch?csv_url=...', { headers: {'x-api-key':'YOUR_KEY'} });\nconst data = await res.json();</pre>"
        "<pre># Python\nimport requests\nr = requests.get('"+PUBLIC_BASE_URL+"/v1/fetch', params={'csv_url':'...'}, headers={'x-api-key':'YOUR_KEY'})\nprint(r.json())</pre>"
        "</div></div></body></html>"
    )

REQUEST_KEY_HTML = (
    "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — Request a Key")+"</head>"
    "<body><div class='wrap'>"
    "<header><img src='/logo.svg' alt='SheetsJSON logo' style='width:36px;height:36px;margin-right:8px'/><strong>SheetsJSON</strong></header>"
    "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a><a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
    "<div class='card'><h1>Request an API Key</h1>"
    "<p class='hint'>Free keys are issued automatically. Pro/Plus keys are also issued here for demo purposes.</p>"
    "<form method='post' action='/request-key'>"
    "<label>Name</label><input name='name' required />"
    "<label>Email</label><input name='email' type='email' required />"
    "<label>Plan</label>"
    "<select name='plan'>"
    "<option value='free'>Free ("+str(PLANS['free']['monthly_limit'])+" req/mo)</option>"
    "<option value='pro'>Pro ("+str(PLANS['pro']['monthly_limit'])+" req/mo) – $"+str(PLANS['pro']['price'])+"/mo</option>"
    "<option value='plus'>Plus ("+str(PLANS['plus']['monthly_limit'])+" req/mo) – $"+str(PLANS['plus']['price'])+"/mo</option>"
    "</select>"
    "<label>Use case</label><textarea name='use_case' placeholder='How will you use SheetsJSON?'></textarea>"
    "<input name='company' style='display:none' autocomplete='off' />"
    "<div style='margin-top:8px'><button type='submit'>Submit</button></div>"
    "</form>"
    "<p class='hint' style='margin-top:8px'>We’ll show your key on the next screen. (For production, wire payments or approval flow.)</p>"
    "</div></div></body></html>"
)

# /usage page (non-f-string)
USAGE_HTML = (
    "<!doctype html><html lang='en'><head>"
    + _html_head("SheetsJSON — Usage")
    + "</head>"
    + """
<body><div class="wrap">
  <header><img src="/logo.svg" alt="SheetsJSON logo" style="width:36px;height:36px;margin-right:8px"/><strong>SheetsJSON</strong></header>
  <nav><a href="/">Home</a><a href="/examples">Examples</a><a href="/pricing">Pricing & Docs</a><a href="/docs">Swagger</a><a href="/usage">Usage</a><a href="/faq">FAQ</a></nav>
  <div class="card">
    <h1>Check your usage</h1>
    <label>API key</label>
    <input id="key" placeholder="Paste your API key here" />
    <div style="margin-top:8px"><button id="check" type="button">Check Usage</button></div>
    <div id="status" class="hint" style="margin-top:8px">Ready.</div>
  </div>
  <div class="card" style="margin-top:14px">
    <h2>Result</h2>
    <pre id="raw">Waiting…</pre>
    <div id="summary" style="margin-top:10px; display:none">
      <p><strong>Plan:</strong> <span id="plan"></span></p>
      <p><strong>Period:</strong> <span id="period"></span></p>
      <div style="background:#0a0f24;border:1px solid #26335f;border-radius:12px;overflow:hidden">
        <div id="bar" style="height:16px;width:0%"></div>
      </div>
      <small class="hint"><span id="numbers"></span></small>
    </div>
  </div>
  <p class="hint">By using SheetsJSON you agree to our <a href="/terms">Terms</a> and acknowledge our <a href="/privacy">Privacy Policy</a>.</p>
</div>
<script>
const $ = (id) => document.getElementById(id);
function toNum(x){ const n = Number(x); return Number.isFinite(n) ? n : 0; }
function setBar(used, limit){
  const u = toNum(used); const m = Math.max(1, toNum(limit));
  let pct = Math.round((u / m) * 100);
  if (!Number.isFinite(pct) || pct < 0) pct = 0; if (pct > 100) pct = 100;
  const el = $("bar"); if (!el) return; el.style.width = pct + "%";
  el.style.background = pct < 70 ? "#55d38a" : (pct < 90 ? "#e9c46a" : "#ef6f6c");
}
async function run(){
  const key = $("key").value.trim(); if(!key){ $("status").textContent = "Enter your API key."; return; }
  $("status").textContent = "Loading…";
  try{
    const res = await fetch("/v1/usage", { headers: { "x-api-key": key } });
    const text = await res.text();
    try { $("raw").textContent = JSON.stringify(JSON.parse(text), null, 2); } catch { $("raw").textContent = text; }
    if(!res.ok){ $("status").textContent = "HTTP " + res.status; $("summary").style.display="none"; return; }
    const data = JSON.parse(text);
    const used = Number(data.used ?? 0), limit = Number(data.limit ?? 0);
    $("plan").textContent = data.plan || "(unknown)"; $("period").textContent = data.period || "";
    $("numbers").textContent = `${used} of ${limit} requests used`; setBar(used, limit);
    $("summary").style.display = "block"; $("status").textContent = "HTTP " + res.status;
  }catch(e){ $("status").textContent = "Error"; $("raw").textContent = "Error: " + e; }
}
$("check").addEventListener("click", run);
</script>
</body></html>
"""
)

PRIVACY_HTML = (
    "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — Privacy Policy")+"</head>"
    "<body><div class='wrap'><header><img src='/logo.svg' alt='SheetsJSON logo' style='width:36px;height:36px;margin-right:8px'/>"
    "<strong>SheetsJSON</strong></header><nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a>"
    "<a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
    "<div class='card'><h1>Privacy Policy</h1>"
    "<ul><li><strong>Data we store:</strong> API key usage counts (per month), API keys, and key request submissions (name/email/use case).</li>"
    "<li><strong>Retention:</strong> Usage counts and keys are kept while the service is active. Key requests may be retained for support and abuse prevention.</li>"
    "<li><strong>Security:</strong> All traffic is over HTTPS. Keys are required for API calls. You should not send private or sensitive data in your sheets.</li>"
    "<li><strong>Contact:</strong> For questions or data removal, email: <em>(add your support email)</em>.</li></ul>"
    "</div></div></body></html>"
)

TERMS_HTML = (
    "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — Terms of Service")+"</head>"
    "<body><div class='wrap'><header><img src='/logo.svg' alt='SheetsJSON logo' style='width:36px;height:36px;margin-right:8px'/>"
    "<strong>SheetsJSON</strong></header><nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a>"
    "<a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
    "<div class='card'><h1>Terms of Service</h1>"
    "<ul><li><strong>Acceptable Use:</strong> Only use published Google Sheets CSV links.</li>"
    "<li><strong>Rate Limits:</strong> We may throttle or block excessive requests.</li>"
    "<li><strong>Availability:</strong> Service is provided “as is” without warranty. Free tier may sleep after inactivity.</li>"
    "<li><strong>Liability:</strong> We’re not liable for lost data or downstream issues caused by your use of this service.</li>"
    "<li><strong>Changes:</strong> We may change pricing/limits/terms with notice on this site.</li></ul>"
    "</div></div></body></html>"
)

def _examples_html() -> str:
    return (
        "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — Examples")+"</head>"
        "<body><div class='wrap'><header><img src='/logo.svg' alt='SheetsJSON logo'/><strong>SheetsJSON</strong></header>"
        "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a><a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
        "<div class='card'><h1>Examples</h1><p>These demo datasets are hosted on this domain so you can try filtering/sorting instantly.</p>"
        "<div class='cards'>"
        "<div class='card'><h3>Products</h3><p>Filter active items under $20 and sort by price.</p>"
        "<a class='btn' href='/?csv="+PUBLIC_BASE_URL+"/demo/csv/1&filter=status%3Aactive&filter=price%3C20&order=price%3Anum&autorun=1'>Open in Playground →</a></div>"
        "<div class='card'><h3>Employees</h3><p>Select name, role, city. Sort by salary desc.</p>"
        "<a class='btn' href='/?csv="+PUBLIC_BASE_URL+"/demo/csv/2&select=name,role,city&order=-salary%3Anum&autorun=1'>Open in Playground →</a></div>"
        "<div class='card'><h3>Events</h3><p>Show only open events, limit 2.</p>"
        "<a class='btn' href='/?csv="+PUBLIC_BASE_URL+"/demo/csv/3&filter=status%3Aopen&limit=2&autorun=1'>Open in Playground →</a></div>"
        "</div><p class='hint' style='margin-top:10px'>Have a Sheet? Publish to web → CSV and paste the link on the Home page.</p>"
        "</div></div></body></html>"
    )

FAQ_HTML = (
    "<!doctype html><html lang='en'><head>"+_html_head("SheetsJSON — FAQ")+"</head>"
    "<body><div class='wrap'><header><img src='/logo.svg' alt='SheetsJSON logo'/><strong>SheetsJSON</strong></header>"
    "<nav><a href='/'>Home</a><a href='/examples'>Examples</a><a href='/pricing'>Pricing & Docs</a><a href='/docs'>Swagger</a><a href='/usage'>Usage</a><a href='/faq'>FAQ</a></nav>"
    "<div class='card'><h1>FAQ</h1>"
    "<h3>What links are allowed?</h3><p>Published Google Sheets CSV links (<em>File → Share → Publish to web → CSV</em>). For demos, we also allow <code>"+PUBLIC_BASE_URL+"/demo/csv/…</code>.</p>"
    "<h3>Do you store my data?</h3><p>No sheet data is stored. We keep API keys and monthly usage counts. See <a href='/privacy'>Privacy</a>.</p>"
    "<h3>How do filters work?</h3><p>String: <code>col:value</code>, <code>col!=v</code>, <code>col~v</code>, <code>col^v</code>, <code>col$v</code>.<br/>Numeric: <code>col&gt;=n</code>, <code>&lt;=</code>, <code>&gt;</code>, <code>&lt;</code>. Sort: <code>order=price:num</code> or <code>-price:num</code>. Select columns with <code>select=col1,col2</code>.</p>"
    "<h3>How do I publish to CSV?</h3><ol>"
    "<li>Open your Google Sheet → File → <strong>Share</strong> → <strong>Publish to web</strong>.</li>"
    "<li>Select the sheet/tab, choose <strong>CSV</strong>, and click <strong>Publish</strong>.</li>"
    "<li>Ensure the link contains <code>/pub</code> and <code>output=csv</code>, then paste it on the Home page.</li></ol>"
    "<h3>Is there caching?</h3><p>Yes. Server caches CSV for <code>CACHE_TTL_SECONDS</code> (default 300s). Client ETag supported—send <code>If-None-Match</code> to skip body.</p>"
    "<h3>What are limits?</h3><p>Free: "+str(PLANS['free']['monthly_limit'])+"/mo. Pro: "+str(PLANS['pro']['monthly_limit'])+"/mo. Plus: "+str(PLANS['plus']['monthly_limit'])+"/mo.</p>"
    "</div></div></body></html>"
)

# ---------- Demo CSV endpoints ----------
@app.get("/demo/csv/1", response_class=PlainTextResponse)
def demo_csv_1():
    return PlainTextResponse(
        "id,name,category,price,status\n"
        "1,Widget A,Gadgets,19.99,active\n"
        "2,Widget B,Gadgets,24.50,active\n"
        "3,Thing C,Tools,8.00,archived\n"
        "4,Thing D,Tools,12.25,active\n"
        "5,Gizmo E,Accessories,5.50,active\n",
        media_type="text/csv"
    )

@app.get("/demo/csv/2", response_class=PlainTextResponse)
def demo_csv_2():
    return PlainTextResponse(
        "id,name,role,city,salary\n"
        "101,Alice Johnson,Engineer,Denver,115000\n"
        "102,Bob Smith,Designer,Austin,98000\n"
        "103,Carla Reyes,Engineer,NYC,142000\n"
        "104,David Kim,Support,Remote,70000\n"
        "105,Erin Patel,PM,NYC,128000\n",
        media_type="text/csv"
    )

@app.get("/demo/csv/3", response_class=PlainTextResponse)
def demo_csv_3():
    return PlainTextResponse(
        "date,title,city,seats,status\n"
        "2025-08-01,Launch Party,New York,120,open\n"
        "2025-08-05,Webinar: Sheets → JSON,Online,500,open\n"
        "2025-08-10,Meetup,Denver,80,waitlist\n"
        "2025-08-15,Workshop,Austin,40,cancelled\n",
        media_type="text/csv"
    )

# ---------- Routes: pages ----------
@app.get("/", response_class=HTMLResponse)
def home(): return HTMLResponse(_home_html())

@app.get("/examples", response_class=HTMLResponse)
def examples_page(): return HTMLResponse(_examples_html())

@app.get("/pricing", response_class=HTMLResponse)
def pricing(): return HTMLResponse(_pricing_html())

@app.get("/request-key", response_class=HTMLResponse)
def request_key_form(): return HTMLResponse(REQUEST_KEY_HTML)

@app.get("/usage", response_class=HTMLResponse)
def usage_page(): return HTMLResponse(USAGE_HTML)

@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(): return HTMLResponse(PRIVACY_HTML)

@app.get("/terms", response_class=HTMLResponse)
def terms_page(): return HTMLResponse(TERMS_HTML)

@app.get("/faq", response_class=HTMLResponse)
def faq_page(): return HTMLResponse(FAQ_HTML)

# ---------- Key request (demo flow) ----------
@app.post("/request-key")
async def request_key_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    plan: str = Form("free"),
    use_case: str = Form(""),
    company: str = Form("")  # honeypot
):
    if company.strip():
        return HTMLResponse("<h3>Thanks!</h3>", status_code=200)

    payload = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "name": name.strip()[:200],
        "email": email.strip()[:200],
        "plan": plan.strip().lower()[:50],
        "use_case": use_case.strip()[:5000],
        "ip": request.client.host if request.client else None,
        "ua": request.headers.get("user-agent", ""),
        "mode": KEY_REQUEST_MODE,
    }

    if KEY_REQUEST_MODE == "email" and SMTP_HOST and SMTP_USER and SMTP_PASS:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[SheetsJSON] Key request ({payload['plan']}) — {payload['name']}"
            msg["From"] = SMTP_USER; msg["To"] = KEY_REQUEST_TO
            msg.set_content(json.dumps(payload, indent=2))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
        except Exception as e:
            with open(KEY_REQUEST_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({**payload, "email_error": str(e)}) + "\n")
    else:
        with open(KEY_REQUEST_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

    key_text = issue_key(payload["plan"]) if KEY_AUTO_ISSUE else None

    if key_text:
        key_html = (
            "<p>Your <strong>"+PLANS[payload['plan']]['label']+"</strong> API key:</p>"
            "<pre style='background:#0a0f24;border:1px solid #26335f;border-radius:8px;padding:12px'>"+key_text+"</pre>"
            "<p class='hint'>Limit: "+str(PLANS[payload['plan']]['monthly_limit'])+" requests / month. "
            "Use header <code>x-api-key</code> or query <code>?key=</code>.</p>"
        )
    else:
        key_html = "<p>We’ll email your key shortly.</p>"

    return HTMLResponse(
        "<!doctype html><meta charset='utf-8'><title>Thanks</title>"
        "<body style='font-family:system-ui;padding:2rem;background:#0b1020;color:#eef2ff'>"
        "<h2>Thanks — your request was received.</h2>"
        + key_html +
        "<p><a style='color:#9cc2ff' href='/'>← Back to Home</a></p></body>",
        status_code=200
    )

# ---------- SEO: robots & sitemap (auto-detect host) ----------
@app.get("/robots.txt", response_class=PlainTextResponse, tags=["SEO"])
def robots(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    return PlainTextResponse("User-agent: *\nAllow: /\nSitemap: " + base + "/sitemap.xml\n")

@app.get("/sitemap.xml", tags=["SEO"])
def sitemap(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    urls = ["/", "/examples", "/pricing", "/usage", "/faq", "/privacy", "/terms"]
    items = "".join("<url><loc>"+base+p+"</loc></url>" for p in urls)
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        + items + "</urlset>"
    )
    return FastAPIResponse(content=xml, media_type="application/xml")

# ---------- Health ----------
@app.get("/healthz")
def healthz(): return {"ok": True, "version": "0.13.0"}

# ---------- API ----------
@app.get("/v1/fetch", tags=["API"], description="Paste a Google Sheets **Publish to web → CSV** link.")
def fetch(
    request: Request, response: Response,
    csv_url: str = Query(..., description="Google Sheets Publish-to-web CSV", example="https://docs.google.com/spreadsheets/d/XXX/pub?output=csv"),
    select: Optional[str] = Query(None, description="Comma-separated columns", example="name,email"),
    filter: Optional[List[str]] = Query(None, description="col:value | col!=v | col~v | col^v | col$v | numeric > < >= <=", example=["status:active","name~ali","age>=21"]),
    order: Optional[str] = Query(None, description="string: col  |  numeric: col:num (desc with -)", example="-price:num"),
    limit: Optional[int] = Query(None, ge=1, le=10000, description="Max rows", example=50),
    offset: Optional[int] = Query(0, ge=0, description="Rows to skip", example=0),
    cache_bypass: Optional[int] = Query(0, description="1 to refetch CSV", example=0),
    api_key_header: Optional[str] = Header(None, alias="x-api-key", description="Your API key", example="FREE_EXAMPLE_KEY_123"),
    key: Optional[str] = Query(None, description="API key (alt)", example="FREE_EXAMPLE_KEY_123"),
):
    api_key = require_and_track_key(api_key_header, key)
    rl_or_429(request, api_key)
    validate_csv_url(csv_url)
    rows, raw_sha = fetch_csv_rows(csv_url, bypass_cache=bool(cache_bypass))
    data = apply_filters(rows, select=select, filters=filter, order=order, limit=limit, offset=offset)

    qnorm = json.dumps({"select": select, "filter": filter, "order": order, "limit": limit, "offset": offset}, sort_keys=True, separators=(",",":"))
    etag = hashlib.sha1((raw_sha + "|" + qnorm + "|" + str(len(data))).encode("utf-8")).hexdigest()
    response.headers["ETag"] = etag
    inm = request.headers.get("if-none-match")
    if inm and inm == etag:
        return Response(status_code=304)

    body = {"rows": data, "meta": {
        "total_rows": len(rows), "returned": len(data),
        "cached_seconds_left": max(0, CACHE_TTL - int(time.time() - _cache.get(csv_url, {}).get("ts", 0))),
        "cache_ttl_seconds": CACHE_TTL, "api_key": api_key if REQUIRE_API_KEY else None, "etag": etag,
    }}
    return JSONResponse(content=body, headers={"ETag": etag})

# ---------- Account ----------
@app.get("/v1/usage", tags=["Account"])
def usage(
    api_key_header: Optional[str] = Header(None, alias="x-api-key", description="Your API key", example="FREE_EXAMPLE_KEY_123"),
    key: Optional[str] = Query(None, description="API key (alt)", example="FREE_EXAMPLE_KEY_123"),
):
    if not REQUIRE_API_KEY:
        return {"message": "API key requirement is disabled."}
    api_key = api_key_header or key
    if not api_key or get_limit_for_key(api_key) <= 0:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    plan = get_plan_for_key(api_key)
    return {"api_key": api_key, "plan": plan, "period": current_period(),
            "used": get_usage(api_key), "limit": get_limit_for_key(api_key)}

# ---------- Admin (HTTP Basic) ----------
security = HTTPBasic()
def admin_guard(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compareDigest(credentials.username, ADMIN_USER) if hasattr(secrets, "compareDigest") else secrets.compare_digest(credentials.username, ADMIN_USER)
    p_ok = secrets.compareDigest(credentials.password, ADMIN_PASS) if hasattr(secrets, "compareDigest") else secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return True

@app.get("/admin/keys", tags=["Admin"])
def admin_keys_page(auth: bool = Depends(admin_guard)):
    if KEYS_BACKEND == "db":
        items = keys_db_list(1000)
    else:
        items = [{"api_key": k, "plan": v.get("plan","?"), "monthly_limit": v.get("monthly_limit","?"), "created_at":"(file)"} for k,v in load_keys_file().items()]
    rows = []
    for item in items:
        k = item["api_key"]; plan = item["plan"]; lim = item["monthly_limit"]
        rows.append(
            "<tr><td><code>"+k+"</code></td><td>"+str(plan)+"</td><td>"+str(lim)+"</td>"
            "<td><form method='post' action='/admin/keys/update' style='display:inline'>"
            "<input type='hidden' name='api_key' value='"+k+"'/><select name='plan'>"
            "<option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select>"
            "<input name='monthly_limit' type='number' placeholder='(keep)' style='width:120px'/>"
            "<button class='btn' type='submit'>Update</button></form> "
            "<form method='post' action='/admin/keys/revoke' style='display:inline;margin-left:6px'>"
            "<input type='hidden' name='api_key' value='"+k+"'/><button class='btn' type='submit'>Revoke</button></form></td></tr>"
        )
    table = "\n".join(rows) or "<tr><td colspan='4'><em>No keys yet.</em></td></tr>"
    html = (
        "<!doctype html><html><head>"+_html_head("Admin — Keys")+"</head><body>"
        "<div class='wrap'><div class='card'><h1>Admin — Keys</h1>"
        "<form method='post' action='/admin/keys/mint' style='margin:8px 0'>"
        "<strong>Mint:</strong> plan "
        "<select name='plan'><option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select> "
        "limit <input name='monthly_limit' type='number' placeholder='(default)' style='width:120px'/> "
        "<button class='btn' type='submit'>Create</button></form>"
        "<table><thead><tr><th>API key</th><th>Plan</th><th>Monthly limit</th><th>Actions</th></tr></thead><tbody>"
        + table +
        "</tbody></table></div></div></body></html>"
    )
    return HTMLResponse(html)

@app.post("/admin/keys/mint", tags=["Admin"])
def admin_mint_key(plan: str = Form("free"), monthly_limit: Optional[int] = Form(None), auth: bool = Depends(admin_guard)):
    k = issue_key(plan, monthly_limit)
    return PlainTextResponse("Created key: " + k + "\n\nGo back: /admin/keys")

@app.post("/admin/keys/update", tags=["Admin"])
def admin_update_key(api_key: str = Form(...), plan: str = Form("free"), monthly_limit: Optional[int] = Form(None), auth: bool = Depends(admin_guard)):
    if KEYS_BACKEND == "db":
        if not keys_db_get(api_key):
            raise HTTPException(status_code=404, detail="Key not found")
        p = plan.lower() if plan.lower() in PLANS else "free"
        keys_db_update(api_key, p, monthly_limit if monthly_limit not in (None, "") else None)
    else:
        keys = load_keys_file()
        if api_key not in keys: raise HTTPException(status_code=404, detail="Key not found")
        keys[api_key]["plan"] = plan.lower() if plan.lower() in PLANS else "free"
        if monthly_limit not in (None, ""):
            keys[api_key]["monthly_limit"] = int(monthly_limit)
        save_keys_file(keys)
    return PlainTextResponse("Updated.\n\nGo back: /admin/keys")

@app.post("/admin/keys/revoke", tags=["Admin"])
def admin_revoke_key(api_key: str = Form(...), auth: bool = Depends(admin_guard)):
    if KEYS_BACKEND == "db":
        keys_db_delete(api_key)
    else:
        keys = load_keys_file()
        if api_key in keys:
            del keys[api_key]
            save_keys_file(keys)
    return PlainTextResponse("Revoked (if it existed).\n\nGo back: /admin/keys")

# ---------- Billing (Stripe) ----------
def orders_insert(session_id: str, email: Optional[str], plan: str,
                  api_key: Optional[str], status: str,
                  customer_id: Optional[str] = None, subscription_id: Optional[str] = None):
    with db_conn() as con:
        cur = con.cursor()
        if DB_IS_PG:
            q = """INSERT INTO orders(session_id,email,plan,api_key,status,created_at,customer_id,subscription_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (session_id) DO UPDATE SET
                     email=EXCLUDED.email, plan=EXCLUDED.plan, api_key=COALESCE(orders.api_key, EXCLUDED.api_key),
                     status=EXCLUDED.status, customer_id=COALESCE(orders.customer_id, EXCLUDED.customer_id),
                     subscription_id=COALESCE(orders.subscription_id, EXCLUDED.subscription_id)"""
            cur.execute(q, (session_id, email, plan, api_key, status, datetime.datetime.utcnow().isoformat()+"Z", customer_id, subscription_id))
        else:
            # SQLite upsert-ish
            existing = orders_get(session_id)
            if existing:
                q = """UPDATE orders SET email=?, plan=?, api_key=COALESCE(api_key, ?), status=?,
                       customer_id=COALESCE(customer_id, ?), subscription_id=COALESCE(subscription_id, ?) WHERE session_id=?"""
                cur.execute(q, (email, plan, api_key, status, customer_id, subscription_id, session_id))
            else:
                q = """INSERT INTO orders(session_id,email,plan,api_key,status,created_at,customer_id,subscription_id)
                       VALUES (?,?,?,?,?,?,?,?)"""
                cur.execute(q, (session_id, email, plan, api_key, status, datetime.datetime.utcnow().isoformat()+"Z", customer_id, subscription_id))
        con.commit()

def orders_get(session_id: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE session_id=%s" if DB_IS_PG else \
            "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE session_id=?"
        cur.execute(q, (session_id,))
        row = cur.fetchone()
        if not row: return None
        return {"session_id": row[0], "email": row[1], "plan": row[2], "api_key": row[3], "status": row[4], "created_at": row[5],
                "customer_id": row[6], "subscription_id": row[7]}

def orders_find_by_customer(customer_id: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        if DB_IS_PG:
            q = """SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id
                   FROM orders WHERE customer_id=%s ORDER BY created_at DESC LIMIT 1"""
            cur.execute(q, (customer_id,))
        else:
            q = """SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id
                   FROM orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 1"""
            cur.execute(q, (customer_id,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "session_id": row[0],
            "email": row[1],
            "plan": row[2],
            "api_key": row[3],
            "status": row[4],
            "created_at": row[5],
            "customer_id": row[6],
            "subscription_id": row[7],
        }

@app.post("/billing/checkout", tags=["Billing"])
def billing_checkout(plan: str = Form(...)):
    if not SUBSCRIBE_ENABLED:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    plan_l = (plan or "").lower()
    if plan_l not in ("pro", "plus"):
        raise HTTPException(status_code=400, detail="Invalid plan")
    price_id = STRIPE_PRICE_PRO if plan_l == "pro" else STRIPE_PRICE_PLUS
    params = dict(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        allow_promotion_codes=True,
        success_url=f"{PUBLIC_BASE_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{PUBLIC_BASE_URL}/pricing",
        metadata={"plan": plan_l},
    )
    if STRIPE_AUTOMATIC_TAX:
        params["automatic_tax"] = {"enabled": True}
    try:
        session = stripe.checkout.Session.create(**params)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {e}")
    #return HTMLResponse(f"<!doctype html><meta charset='utf-8'><script>location.href='{session.url}';</script>")
    return RedirectResponse(url=session.url, status_code=303)

# Customer Portal (Manage billing)
@app.post("/billing/portal", tags=["Billing"])
def billing_portal(session_id: str = Form(...)):
    if not SUBSCRIBE_ENABLED:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    rec = orders_get(session_id)
    if not rec or not rec.get("customer_id"):
        raise HTTPException(status_code=404, detail="Order not found or missing customer")
    sess = stripe.billing_portal.Session.create(
        customer=rec["customer_id"],
        return_url=f"{PUBLIC_BASE_URL}/pricing"
    )
    #return HTMLResponse('<!doctype html><meta charset="utf-8"><script>location.href="'+sess.url+'";</script>')
    return RedirectResponse(url=sess.url, status_code=303)

@app.get("/billing/success", response_class=HTMLResponse, tags=["Billing"])
def billing_success(session_id: str = Query(...)):
    rec = orders_get(session_id)
    if rec and rec.get("api_key"):
        key_html = (
            "<p>Your <strong>"+PLANS[rec['plan']]['label']+"</strong> API key:</p>"
            "<pre style='background:#0a0f24;border:1px solid #26335f;border-radius:8px;padding:12px'>"+rec['api_key']+"</pre>"
            "<p class='hint'>Stored for "+(rec.get("email") or "(no email)")+".</p>"
        )
    else:
        key_html = "<p>Thanks! We’re finalizing your subscription. This page will show your key as soon as the payment completes—refresh in a few seconds.</p>"
    plan_js = (rec.get("plan","") if rec else "")
    return HTMLResponse(
        "<!doctype html><html><head>"+_html_head("SheetsJSON — Thanks!")+"</head>"
        "<body><div class='wrap'><div class='card'>"
        "<h1>Payment successful</h1>"+key_html+
        "<form method='post' action='/billing/portal' style='display:inline'>"
        "<input type='hidden' name='session_id' value='"+session_id+"'/><button class='btn' type='submit'>Manage billing</button></form>"
        "<a class='btn' style='margin-left:8px' href='/'>Go to Home</a>"
        "<a class='btn' style='margin-left:8px' href='/pricing'>Docs</a>"
        "</div></div>"
        "<script>if(window.plausible){plausible('SubscribeSuccess',{props:{plan:'"+plan_js+"'}});}</script>"
        "</body></html>"
    )

@app.post("/stripe/webhook", tags=["Billing"])
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook signature error: {e}")

    t = event["type"]

    if t == "checkout.session.completed":
        s = event["data"]["object"]
        session_id = s["id"]
        plan = ((s.get("metadata") or {}).get("plan") or "pro").lower()
        email = (s.get("customer_details") or {}).get("email") or s.get("customer_email")
        customer_id = s.get("customer")
        subscription_id = s.get("subscription")

        existing = orders_get(session_id)
        if existing and existing.get("api_key"):
            return {"ok": True}

        k = issue_key(plan)
        orders_insert(session_id, email, plan, k, "completed", customer_id, subscription_id)

        if SMTP_HOST and SMTP_USER and SMTP_PASS and email:
            try:
                msg = EmailMessage()
                msg["Subject"] = "Your SheetsJSON "+PLANS[plan]["label"]+" API Key"
                msg["From"] = SMTP_USER; msg["To"] = email
                msg.set_content(
                    "Thanks for subscribing to SheetsJSON ("+plan+").\n\n"
                    "Here is your API key:\n\n"+k+"\n\n"
                    "Docs: "+PUBLIC_BASE_URL+"/pricing\nUsage: "+PUBLIC_BASE_URL+"/usage\n"
                )
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s2:
                    s2.starttls(); s2.login(SMTP_USER, SMTP_PASS); s2.send_message(msg)
            except Exception:
                pass

    elif t == "customer.subscription.deleted":
        sub = event["data"]["object"]
        customer_id = sub.get("customer")
        rec = orders_find_by_customer(customer_id) if customer_id else None
        if rec and rec.get("api_key"):
            if KEYS_BACKEND == "db":
                keys_db_update(rec["api_key"], plan=CANCEL_DOWNGRADE_PLAN, monthly_limit=PLANS.get(CANCEL_DOWNGRADE_PLAN, PLANS["free"])["monthly_limit"])
            else:
                keys = load_keys_file()
                if rec["api_key"] in keys:
                    keys[rec["api_key"]]["plan"] = CANCEL_DOWNGRADE_PLAN
                    keys[rec["api_key"]]["monthly_limit"] = PLANS.get(CANCEL_DOWNGRADE_PLAN, PLANS["free"])["monthly_limit"]
                    save_keys_file(keys)

    elif t == "invoice.payment_failed":
        inv = event["data"]["object"]
        customer_id = inv.get("customer")
        rec = orders_find_by_customer(customer_id) if customer_id else None
        if rec and rec.get("api_key"):
            if KEYS_BACKEND == "db":
                keys_db_update(rec["api_key"], plan=CANCEL_DOWNGRADE_PLAN, monthly_limit=PLANS.get(CANCEL_DOWNGRADE_PLAN, PLANS["free"])["monthly_limit"])
            else:
                keys = load_keys_file()
                if rec["api_key"] in keys:
                    keys[rec["api_key"]]["plan"] = CANCEL_DOWNGRADE_PLAN
                    keys[rec["api_key"]]["monthly_limit"] = PLANS.get(CANCEL_DOWNGRADE_PLAN, PLANS["free"])["monthly_limit"]
                    save_keys_file(keys)

    return {"ok": True}

# ---------- Startup ----------
@app.on_event("startup")
def _startup():
    db_init()

# ---------- Health/debug (optional) ----------
@app.get("/_debug/routes")
def _debug_routes():
    return [{"path": r.path, "methods": sorted(list(getattr(r, "methods", [])))} for r in app.routes]

if __name__ == "__main__":
    uvicorn_run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
