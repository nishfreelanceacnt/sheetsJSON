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

SENTRY_DSN = os.getenv("SENTRY_DSN", "").strip()
if SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.05)
    except Exception:
        pass

app = FastAPI(
    title="SheetsJSON",
    version="1.0.0",
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

CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")
cors_origins = ["*"] if CORS_ALLOW_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_methods=["*"], allow_headers=["*"])

CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", "300"))
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")

KEYS_BACKEND = os.getenv("KEYS_BACKEND", "db").lower()
KEYS_PATH = os.getenv("KEYS_PATH", "keys.json")

USAGE_DB = os.getenv("USAGE_DB_PATH", "usage.db")
DATABASE_URL = os.getenv("DATABASE_URL")
DB_IS_PG = bool(DATABASE_URL and DATABASE_URL.startswith("postgres"))

KEY_REQUEST_MODE = os.getenv("KEY_REQUEST_MODE", "file")
KEY_REQUEST_FILE = os.getenv("KEY_REQUEST_FILE", "key_requests.jsonl")
KEY_AUTO_ISSUE = os.getenv("KEY_AUTO_ISSUE", "true").lower() in ("1", "true", "yes")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
KEY_REQUEST_TO = os.getenv("KEY_REQUEST_TO", SMTP_USER)

ADMIN_USER = os.getenv("ADMIN_USER") or "admin"
ADMIN_PASS = os.getenv("ADMIN_PASS") or "change-me"
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "90"))

PLANS = {
    "free": {"price": 0,  "monthly_limit": 200,   "label": "Free"},
    "pro":  {"price": 9,  "monthly_limit": 5000,  "label": "Pro"},
    "plus": {"price": 19, "monthly_limit": 25000, "label": "Plus"},
}

STRIPE_SECRET_KEY     = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_PRO      = os.getenv("STRIPE_PRICE_PRO")
STRIPE_PRICE_PLUS     = os.getenv("STRIPE_PRICE_PLUS")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
PUBLIC_BASE_URL       = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
STRIPE_AUTOMATIC_TAX  = os.getenv("STRIPE_AUTOMATIC_TAX", "0").lower() in ("1","true","yes","on")
CANCEL_DOWNGRADE_PLAN = os.getenv("CANCEL_DOWNGRADE_PLAN", "free").lower()

SUBSCRIBE_ENABLED = bool(STRIPE_SECRET_KEY and STRIPE_PRICE_PRO and STRIPE_PRICE_PLUS and PUBLIC_BASE_URL)
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

PLAUSIBLE_DOMAIN = os.getenv("PLAUSIBLE_DOMAIN", "").strip()
GOOGLE_SITE_VERIFICATION = os.getenv("GOOGLE_SITE_VERIFICATION", "").strip()

PUBLIC_HOST = ""
try:
    if PUBLIC_BASE_URL:
        PUBLIC_HOST = urlparse(PUBLIC_BASE_URL).netloc
except Exception:
    PUBLIC_HOST = ""

def _analytics_snippet() -> str:
    if not PLAUSIBLE_DOMAIN:
        return ""
    return f'<script defer data-domain="{PLAUSIBLE_DOMAIN}" src="https://plausible.io/js/script.js"></script>'

def _google_verify_snippet() -> str:
    if not GOOGLE_SITE_VERIFICATION:
        return ""
    return f'<meta name="google-site-verification" content="{GOOGLE_SITE_VERIFICATION}"/>'

class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
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

_cache: Dict[str, Dict] = {}
_rl: Dict[str, List[float]] = {}

def db_conn():
    if DB_IS_PG:
        if not HAS_PG:
            raise RuntimeError("psycopg2 not installed")
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(USAGE_DB)

def db_init():
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS usage (api_key TEXT NOT NULL, period TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (api_key, period));""")
            cur.execute("""CREATE TABLE IF NOT EXISTS keys (api_key TEXT PRIMARY KEY, plan TEXT NOT NULL, monthly_limit INTEGER NOT NULL, created_at TEXT NOT NULL);""")
            cur.execute("""CREATE TABLE IF NOT EXISTS orders (session_id TEXT PRIMARY KEY, email TEXT, plan TEXT NOT NULL, api_key TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, customer_id TEXT, subscription_id TEXT);""")
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS usage (api_key TEXT NOT NULL, period TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (api_key, period))")
            cur.execute("CREATE TABLE IF NOT EXISTS keys (api_key TEXT PRIMARY KEY, plan TEXT NOT NULL, monthly_limit INTEGER NOT NULL, created_at TEXT NOT NULL)")
            cur.execute("CREATE TABLE IF NOT EXISTS orders (session_id TEXT PRIMARY KEY, email TEXT, plan TEXT NOT NULL, api_key TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, customer_id TEXT, subscription_id TEXT)")
            con.commit()
        try:
            with db_conn() as con:
                cur = con.cursor()
                for col in ("customer_id", "subscription_id"):
                    try:
                        cur.execute(f"ALTER TABLE orders ADD COLUMN {col} TEXT")
                        con.commit()
                    except Exception:
                        pass
        except Exception:
            pass

def current_period() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m")

def keys_db_get(api_key: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT plan, monthly_limit, created_at FROM keys WHERE api_key = %s" if DB_IS_PG else \
            "SELECT plan, monthly_limit, created_at FROM keys WHERE api_key = ?"
        cur.execute(q, (api_key,))
        row = cur.fetchone()
        if not row: return None
        return {"plan": row[0], "monthly_limit": int(row[1]), "created_at": row[2]}

def keys_db_insert(api_key: str, plan: str, monthly_limit: int):
    with db_conn() as con:
        cur = con.cursor()
        q = "INSERT INTO keys(api_key, plan, monthly_limit, created_at) VALUES (%s,%s,%s,%s)" if DB_IS_PG else \
            "INSERT INTO keys(api_key, plan, monthly_limit, created_at) VALUES (?,?,?,?)"
        cur.execute(q, (api_key, plan, int(monthly_limit), datetime.datetime.utcnow().isoformat()+"Z"))
        con.commit()

def keys_db_update(api_key: str, plan: Optional[str] = None, monthly_limit: Optional[int] = None):
    if plan is None and monthly_limit is None: return
    with db_conn() as con:
        cur = con.cursor()
        if plan is not None and monthly_limit is not None:
            q = "UPDATE keys SET plan=%s, monthly_limit=%s WHERE api_key=%s" if DB_IS_PG else "UPDATE keys SET plan=?, monthly_limit=? WHERE api_key=?"
            cur.execute(q, (plan, int(monthly_limit), api_key))
        elif plan is not None:
            q = "UPDATE keys SET plan=%s WHERE api_key=%s" if DB_IS_PG else "UPDATE keys SET plan=? WHERE api_key=?"
            cur.execute(q, (plan, api_key))
        else:
            q = "UPDATE keys SET monthly_limit=%s WHERE api_key=%s" if DB_IS_PG else "UPDATE keys SET monthly_limit=? WHERE api_key=?"
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
        return [{"api_key": r[0], "plan": r[1], "monthly_limit": int(r[2]), "created_at": r[3]} for r in cur.fetchall()]

def load_keys_file() -> Dict[str, Dict]:
    if not os.path.exists(KEYS_PATH): return {}
    with open(KEYS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_keys_file(keys: Dict[str, Dict]):
    with open(KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

def issue_key(plan: str, limit_override: Optional[int] = None) -> str:
    plan = plan.lower()
    if plan not in PLANS: plan = "free"
    while True:
        k = uuid.uuid4().hex.upper()
        if KEYS_BACKEND == "db":
            if not keys_db_get(k): break
        else:
            if k not in load_keys_file(): break
    monthly_limit = int(limit_override or PLANS[plan]["monthly_limit"])
    if KEYS_BACKEND == "db":
        keys_db_insert(k, plan, monthly_limit)
    else:
        keys = load_keys_file()
        keys[k] = {"plan": plan, "monthly_limit": monthly_limit}
        save_keys_file(keys)
    return k

def get_limit_for_key(api_key: str) -> int:
    if not api_key: return -1
    def plan_default(plan: str) -> int:
        return int(PLANS.get((plan or "free").lower(), PLANS["free"])["monthly_limit"])
    if KEYS_BACKEND == "db":
        meta = keys_db_get(api_key)
        if not meta: return -1
        return max(int(meta.get("monthly_limit") or 0), plan_default(meta.get("plan")))
    else:
        meta = load_keys_file().get(api_key)
        if not meta: return -1
        return max(int(meta.get("monthly_limit") or 0), plan_default(meta.get("plan")))

def get_plan_for_key(api_key: str) -> Optional[str]:
    if KEYS_BACKEND == "db":
        meta = keys_db_get(api_key)
        return (meta or {}).get("plan")
    return (load_keys_file().get(api_key) or {}).get("plan")

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
            cur.execute("INSERT INTO usage(api_key,period,count) VALUES(%s,%s,0) ON CONFLICT(api_key,period) DO NOTHING", (api_key, period))
            cur.execute("UPDATE usage SET count=count+%s WHERE api_key=%s AND period=%s", (amount, api_key, period))
            cur.execute("SELECT count FROM usage WHERE api_key=%s AND period=%s", (api_key, period))
        else:
            cur.execute("INSERT OR IGNORE INTO usage(api_key,period,count) VALUES(?,?,0)", (api_key, period))
            cur.execute("UPDATE usage SET count=count+? WHERE api_key=? AND period=?", (amount, api_key, period))
            cur.execute("SELECT count FROM usage WHERE api_key=? AND period=?", (api_key, period))
        row = cur.fetchone()
        con.commit()
        return int(row[0]) if row else 0

_num_clean_re = re.compile(r"[,\s]")
_filter_re = re.compile(r"""^\s*(?P<col>[^:~^\$><=!]+?)\s*(?P<op>>=|<=|!=|>|<|~|\^|\$|:)\s*(?P<val>.+?)\s*$""")

def _to_number(s: Optional[str]) -> Optional[float]:
    if s is None: return None
    t = str(s).strip()
    if not t: return None
    if t.startswith("$"): t = t[1:]
    pct = t.endswith("%")
    if pct: t = t[:-1]
    t = _num_clean_re.sub("", t)
    try:
        v = float(t)
        return v / 100.0 if pct else v
    except Exception:
        return None

def _match_filter(row_val: Optional[str], op: str, val: str) -> bool:
    if op in (":", "!=", "~", "^", "$"):
        a = (row_val or "").strip().lower(); b = val.strip().lower()
        return {":": a == b, "!=": a != b, "~": b in a, "^": a.startswith(b), "$": a.endswith(b)}[op]
    if op in (">", "<", ">=", "<="):
        x = _to_number(row_val); y = _to_number(val)
        if x is None or y is None: return False
        return {">": x > y, "<": x < y, ">=": x >= y, "<=": x <= y}[op]
    return False

def _parse_order(order: Optional[str]) -> Tuple[Optional[str], bool, bool]:
    if not order: return None, False, False
    reverse = order.startswith("-")
    core = order[1:] if reverse else order
    numeric = core.endswith(":num")
    if numeric: core = core[:-4]
    return core, reverse, numeric

def validate_csv_url(csv_url: str):
    try:
        u = urlparse(csv_url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid csv_url")
    if u.scheme != "https":
        raise HTTPException(status_code=400, detail="csv_url must be https")
    if PUBLIC_HOST and u.netloc == PUBLIC_HOST and u.path.startswith("/demo/csv/"):
        return
    if not u.netloc.endswith("docs.google.com"):
        raise HTTPException(status_code=400, detail="Only Google Sheets 'Publish to web → CSV' links are allowed")
    if "/pub" not in u.path:
        raise HTTPException(status_code=400, detail="csv_url must be a published CSV (path should contain /pub)")
    qs = parse_qs(u.query)
    if "output" not in qs or "csv" not in [v.lower() for v in qs["output"]]:
        raise HTTPException(status_code=400, detail="csv_url must include output=csv")

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
        dialect = csv.Sniffer().sniff(content_text[:2048], delimiters=[",", ";", "\t", "|"])
        delim = dialect.delimiter
    except Exception:
        delim = ","
    reader = csv.DictReader(io.StringIO(content_text), delimiter=delim)
    rows = [dict(row) for row in reader]
    raw_sha = hashlib.sha1(content_bytes).hexdigest()
    _cache[csv_url] = {"ts": now, "rows": rows, "raw_sha": raw_sha}
    return rows, raw_sha

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
    return out[start:end]

def require_and_track_key(api_key_header: Optional[str], api_key_query: Optional[str]):
    if not REQUIRE_API_KEY: return None
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
    arr = [t for t in _rl.get(bucket, []) if now - t < window]
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
    <stop offset='0%' stop-color='#3b82f6'/><stop offset='100%' stop-color='#60a5fa'/></linearGradient></defs>
  <rect width='256' height='256' rx='52' fill='#0a1628'/>
  <text x='50%' y='54%' text-anchor='middle' dominant-baseline='middle' font-size='148' font-family='ui-sans-serif,system-ui,Segoe UI,Roboto' font-weight='800' fill='url(#g)'>{}</text>
</svg>"""

@app.get("/logo.svg")
def logo_svg():
    return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

@app.get("/favicon.svg")
def favicon_svg():
    return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

# =============================================================================
# HTML LAYER
# =============================================================================

_SHARED_CSS = """
<style>
:root {
  --bg:      #050d1b;
  --surface: #081525;
  --card:    #0c1d34;
  --border:  #1a3356;
  --text:    #dde8ff;
  --muted:   #6887b4;
  --accent:  #3b82f6;
  --accent2: #6366f1;
  --green:   #10b981;
  --r:       12px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--text); font: 15px/1.65 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1,h2,h3,h4 { line-height: 1.25; }
code { background: var(--surface); border: 1px solid var(--border); border-radius: 5px; padding: 1px 6px; font-size: 0.85em; font-family: 'Fira Code','Cascadia Code','Consolas',monospace; }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); padding: 18px 20px; overflow-x: auto; font-size: 13px; line-height: 1.6; font-family: 'Fira Code','Cascadia Code','Consolas',monospace; }
pre code { background: none; border: none; padding: 0; font-size: inherit; }
input, textarea, select { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font: inherit; padding: 10px 14px; width: 100%; outline: none; transition: border-color .15s; }
input:focus, textarea:focus, select:focus { border-color: var(--accent); }
textarea { resize: vertical; min-height: 80px; }
label { display: block; color: var(--muted); font-size: 13px; font-weight: 500; margin-bottom: 6px; margin-top: 14px; letter-spacing: .03em; text-transform: uppercase; }
small { font-size: 12px; color: var(--muted); }

/* Buttons */
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 10px 20px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: opacity .15s, transform .1s; white-space: nowrap; }
.btn:hover { opacity: .88; transform: translateY(-1px); text-decoration: none; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
.btn-outline:hover { border-color: var(--accent); color: var(--accent); }
.btn-sm { padding: 7px 14px; font-size: 13px; }
.btn-danger { background: #ef4444; color: #fff; }

/* Layout */
.wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px; }
.wrap-sm { max-width: 720px; margin: 0 auto; padding: 0 20px; }

/* Nav */
.site-nav { border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; background: rgba(5,13,27,.92); backdrop-filter: blur(12px); }
.site-nav .inner { display: flex; align-items: center; gap: 8px; max-width: 1080px; margin: 0 auto; padding: 0 20px; height: 60px; }
.nav-logo { display: flex; align-items: center; gap: 10px; color: var(--text); font-weight: 700; font-size: 16px; text-decoration: none; }
.nav-logo img { width: 30px; height: 30px; border-radius: 6px; }
.nav-links { display: flex; align-items: center; gap: 4px; margin-left: 16px; flex: 1; }
.nav-links a { color: var(--muted); font-size: 14px; padding: 6px 10px; border-radius: 6px; transition: color .15s, background .15s; }
.nav-links a:hover, .nav-links a.active { color: var(--text); background: rgba(255,255,255,.05); text-decoration: none; }
.nav-cta { margin-left: auto; }

/* Card */
.card { background: var(--card); border: 1px solid var(--border); border-radius: var(--r); padding: 24px; }
.card + .card { margin-top: 16px; }

/* Grid helpers */
.grid-2 { display: grid; gap: 16px; }
.grid-3 { display: grid; gap: 16px; }
@media(min-width:640px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
@media(min-width:800px) { .grid-3 { grid-template-columns: 1fr 1fr 1fr; } }

/* Badge */
.badge { display: inline-block; padding: 3px 10px; border-radius: 99px; font-size: 12px; font-weight: 600; }
.badge-blue { background: rgba(59,130,246,.15); color: #60a5fa; border: 1px solid rgba(59,130,246,.3); }
.badge-green { background: rgba(16,185,129,.15); color: #34d399; border: 1px solid rgba(16,185,129,.3); }

/* Section */
section { padding: 72px 0; }
section h2 { font-size: 28px; font-weight: 700; margin-bottom: 10px; }
section .section-sub { color: var(--muted); font-size: 16px; margin-bottom: 40px; }

/* Footer */
.site-footer { border-top: 1px solid var(--border); padding: 36px 0; margin-top: 80px; }
.site-footer .inner { max-width: 1080px; margin: 0 auto; padding: 0 20px; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; }
.footer-links { display: flex; gap: 20px; flex-wrap: wrap; }
.footer-links a { color: var(--muted); font-size: 13px; }
.footer-links a:hover { color: var(--text); }
.footer-copy { color: var(--muted); font-size: 13px; }

/* Divider */
.divider { border: none; border-top: 1px solid var(--border); margin: 24px 0; }

/* Alert */
.alert { padding: 14px 18px; border-radius: 8px; font-size: 14px; }
.alert-info { background: rgba(59,130,246,.1); border: 1px solid rgba(59,130,246,.25); color: #93c5fd; }
.alert-success { background: rgba(16,185,129,.1); border: 1px solid rgba(16,185,129,.25); color: #6ee7b7; }

/* Key display */
.key-box { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r); padding: 18px 20px; font-family: 'Fira Code','Consolas',monospace; font-size: 15px; letter-spacing: .04em; word-break: break-all; color: #93c5fd; }

/* Table */
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
tbody tr:hover { background: rgba(255,255,255,.02); }
</style>
"""

def _head(title: str, desc: str = "Turn any Google Sheet into a queryable JSON API. Filter, sort, paginate — free tier available.") -> str:
    return (
        '<meta charset="utf-8"/>'
        '<meta name="viewport" content="width=device-width,initial-scale=1"/>'
        f'<title>{title}</title>'
        f'<meta name="description" content="{desc}"/>'
        '<meta property="og:type" content="website"/>'
        f'<meta property="og:title" content="{title}"/>'
        f'<meta property="og:description" content="{desc}"/>'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml"/>'
        + _google_verify_snippet()
        + _analytics_snippet()
        + _SHARED_CSS
    )

def _nav(active: str = "") -> str:
    def lnk(href, label):
        cls = ' class="active"' if active == label else ''
        return f'<a href="{href}"{cls}>{label}</a>'
    return (
        '<nav class="site-nav"><div class="inner">'
        '<a class="nav-logo" href="/"><img src="/logo.svg" alt="SheetsJSON"/>SheetsJSON</a>'
        '<div class="nav-links">'
        + lnk("/playground", "Playground")
        + lnk("/examples", "Examples")
        + lnk("/pricing", "Pricing")
        + lnk("/docs", "API Docs")
        + lnk("/faq", "FAQ")
        + '</div>'
        '<div class="nav-cta"><a class="btn btn-primary btn-sm" href="/request-key">Get API Key</a></div>'
        '</div></nav>'
    )

def _footer() -> str:
    return (
        '<footer class="site-footer"><div class="inner">'
        '<div class="footer-links">'
        '<a href="/">Home</a><a href="/pricing">Pricing</a><a href="/docs">API Docs</a>'
        '<a href="/faq">FAQ</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a>'
        '</div>'
        '<span class="footer-copy">&copy; SheetsJSON</span>'
        '</div></footer>'
    )

def _page(title: str, body: str, active: str = "", desc: str = "") -> str:
    head_args = {"title": title}
    if desc:
        head_args["desc"] = desc
    return "<!doctype html><html lang='en'><head>" + _head(**head_args) + "</head><body>" + _nav(active) + body + _footer() + "</body></html>"

# ---------- Landing Page ----------
def _home_html() -> str:
    body = """
<style>
.hero { padding: 90px 0 80px; text-align: center; position: relative; }
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background: radial-gradient(ellipse 80% 50% at 50% -10%, rgba(59,130,246,.18), transparent);
  pointer-events: none;
}
.hero-badge { margin-bottom: 20px; }
.hero h1 { font-size: clamp(32px, 5vw, 54px); font-weight: 800; letter-spacing: -.02em; margin-bottom: 18px; line-height: 1.15; }
.hero h1 span { background: linear-gradient(135deg, #3b82f6, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.hero-sub { font-size: 18px; color: var(--muted); max-width: 560px; margin: 0 auto 36px; line-height: 1.6; }
.hero-actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; margin-bottom: 56px; }
.hero-code { max-width: 700px; margin: 0 auto; text-align: left; position: relative; }
.hero-code pre { font-size: 13px; line-height: 1.7; border: 1px solid rgba(59,130,246,.25); background: rgba(8,21,37,.95); }
.code-label { font-size: 11px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }
.hl-blue { color: #93c5fd; }
.hl-green { color: #6ee7b7; }
.hl-yellow { color: #fcd34d; }
.hl-muted { color: #6887b4; }

.steps-grid { display: grid; gap: 20px; counter-reset: step; }
@media(min-width:700px){ .steps-grid { grid-template-columns: repeat(3, 1fr); } }
.step { background: var(--card); border: 1px solid var(--border); border-radius: var(--r); padding: 28px 24px; position: relative; }
.step-num { width: 32px; height: 32px; border-radius: 50%; background: rgba(59,130,246,.15); border: 1px solid rgba(59,130,246,.3); color: #60a5fa; font-weight: 700; font-size: 14px; display: flex; align-items: center; justify-content: center; margin-bottom: 14px; }
.step h3 { font-size: 16px; font-weight: 700; margin-bottom: 8px; }
.step p { font-size: 14px; color: var(--muted); line-height: 1.6; }

.features-grid { display: grid; gap: 14px; }
@media(min-width:540px){ .features-grid { grid-template-columns: repeat(2, 1fr); } }
@media(min-width:900px){ .features-grid { grid-template-columns: repeat(3, 1fr); } }
.feat { background: var(--card); border: 1px solid var(--border); border-radius: var(--r); padding: 22px; }
.feat-icon { font-size: 24px; margin-bottom: 12px; }
.feat h3 { font-size: 15px; font-weight: 700; margin-bottom: 6px; }
.feat p { font-size: 13px; color: var(--muted); line-height: 1.6; }

.pricing-section { text-align: center; }
.pricing-grid { display: grid; gap: 16px; max-width: 860px; margin: 0 auto; }
@media(min-width:700px){ .pricing-grid { grid-template-columns: repeat(3, 1fr); } }
.plan { background: var(--card); border: 1px solid var(--border); border-radius: var(--r); padding: 28px 24px; text-align: left; }
.plan.featured { border-color: rgba(59,130,246,.5); background: linear-gradient(135deg, rgba(59,130,246,.08), var(--card)); }
.plan-name { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-bottom: 10px; }
.plan-price { font-size: 36px; font-weight: 800; letter-spacing: -.02em; margin-bottom: 4px; }
.plan-price span { font-size: 15px; font-weight: 400; color: var(--muted); }
.plan-desc { font-size: 13px; color: var(--muted); margin-bottom: 20px; }
.plan ul { list-style: none; margin-bottom: 24px; }
.plan ul li { font-size: 14px; padding: 5px 0; color: var(--muted); display: flex; align-items: flex-start; gap: 8px; }
.plan ul li::before { content: '✓'; color: var(--green); font-weight: 700; flex-shrink: 0; }
.plan-cta { margin-top: auto; }

.cta-band { background: linear-gradient(135deg, rgba(59,130,246,.12), rgba(99,102,241,.08)); border: 1px solid rgba(59,130,246,.2); border-radius: 20px; padding: 56px 40px; text-align: center; }
.cta-band h2 { font-size: 28px; font-weight: 800; margin-bottom: 12px; }
.cta-band p { color: var(--muted); margin-bottom: 28px; font-size: 16px; }
</style>

<div class="hero">
  <div class="wrap">
    <div class="hero-badge"><span class="badge badge-blue">Free tier — no credit card needed</span></div>
    <h1>Turn any Google Sheet into a<br/><span>queryable JSON API</span></h1>
    <p class="hero-sub">Publish your sheet once. Filter, sort, and paginate from any app, script, or dashboard — no backend required.</p>
    <div class="hero-actions">
      <a href="/request-key" class="btn btn-primary">Get your free API key</a>
      <a href="/playground" class="btn btn-outline">Try the Playground &rarr;</a>
    </div>
    <div class="hero-code">
      <div class="code-label">Your API call</div>
      <pre><code><span class="hl-muted">GET</span> <span class="hl-blue">/v1/fetch</span>?csv_url=<span class="hl-yellow">YOUR_SHEET_URL</span>&amp;filter=<span class="hl-green">status:active</span>&amp;order=<span class="hl-green">-price:num</span>&amp;limit=10
<span class="hl-muted">Header:</span> x-api-key: YOUR_KEY</code></pre>
      <div class="code-label" style="margin-top:16px">Response</div>
      <pre><code>{
  <span class="hl-blue">"rows"</span>: [
    { <span class="hl-blue">"name"</span>: <span class="hl-yellow">"Widget A"</span>, <span class="hl-blue">"price"</span>: <span class="hl-yellow">"24.50"</span>, <span class="hl-blue">"status"</span>: <span class="hl-yellow">"active"</span> },
    { <span class="hl-blue">"name"</span>: <span class="hl-yellow">"Widget B"</span>, <span class="hl-blue">"price"</span>: <span class="hl-yellow">"19.99"</span>, <span class="hl-blue">"status"</span>: <span class="hl-yellow">"active"</span> }
  ],
  <span class="hl-blue">"meta"</span>: { <span class="hl-blue">"total_rows"</span>: <span class="hl-green">5</span>, <span class="hl-blue">"returned"</span>: <span class="hl-green">2</span>, <span class="hl-blue">"cached_seconds_left"</span>: <span class="hl-green">287</span> }
}</code></pre>
    </div>
  </div>
</div>

<section style="padding-top:0">
  <div class="wrap">
    <h2>How it works</h2>
    <p class="section-sub">Three steps from spreadsheet to live API.</p>
    <div class="steps-grid">
      <div class="step"><div class="step-num">1</div><h3>Publish your sheet</h3><p>In Google Sheets: <strong>File → Share → Publish to web</strong>, select your tab, choose <strong>CSV</strong>, and click Publish. Copy the link.</p></div>
      <div class="step"><div class="step-num">2</div><h3>Build your query</h3><p>Pass the CSV URL to <code>/v1/fetch</code> with your API key. Add <code>filter</code>, <code>order</code>, <code>select</code>, and <code>limit</code> params as needed.</p></div>
      <div class="step"><div class="step-num">3</div><h3>Use the JSON</h3><p>Get clean JSON back. Plug it into your React app, Webflow site, n8n automation, Google Apps Script — anywhere.</p></div>
    </div>
  </div>
</section>

<section>
  <div class="wrap">
    <h2>Everything you need</h2>
    <p class="section-sub">Powerful filtering and caching built in. No config needed.</p>
    <div class="features-grid">
      <div class="feat"><div class="feat-icon">&#x1F50D;</div><h3>Filter by any column</h3><p>Exact match, contains, starts/ends with, and numeric comparisons. Stack multiple filters on one request.</p></div>
      <div class="feat"><div class="feat-icon">&#x2195;&#xFE0F;</div><h3>Sort &amp; paginate</h3><p>String or numeric sort, ascending or descending. Use <code>limit</code> and <code>offset</code> for pagination.</p></div>
      <div class="feat"><div class="feat-icon">&#x26A1;</div><h3>Smart caching</h3><p>Server-side 5-minute cache cuts Sheet API calls. ETag support lets clients skip the body with <code>304 Not Modified</code>.</p></div>
      <div class="feat"><div class="feat-icon">&#x1F9E9;</div><h3>Embed anywhere</h3><p>Drop a single <code>&lt;script&gt;</code> tag to render a searchable, sortable table in Webflow, Framer, or any HTML page.</p></div>
      <div class="feat"><div class="feat-icon">&#x1F511;</div><h3>API key security</h3><p>Monthly request limits per key. Upgrade, downgrade, or revoke keys anytime via the admin panel.</p></div>
      <div class="feat"><div class="feat-icon">&#x1F6E1;&#xFE0F;</div><h3>Privacy first</h3><p>We never store your spreadsheet data. Only API keys and monthly usage counts are persisted.</p></div>
    </div>
  </div>
</section>

<section class="pricing-section">
  <div class="wrap">
    <h2>Simple pricing</h2>
    <p class="section-sub">Start free. Upgrade when you need more.</p>
    """ + _pricing_cards() + """
  </div>
</section>

<section>
  <div class="wrap">
    <div class="cta-band">
      <h2>Ready to ship?</h2>
      <p>Get your free API key and make your first request in under two minutes.</p>
      <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
        <a href="/request-key" class="btn btn-primary">Get free API key</a>
        <a href="/playground" class="btn btn-outline">Open Playground</a>
      </div>
    </div>
  </div>
</section>
"""
    return _page("SheetsJSON — Google Sheets to JSON API", body)


def _pricing_cards(show_cta: bool = True) -> str:
    sub_on = SUBSCRIBE_ENABLED
    def pro_btn():
        if not sub_on: return '<span style="font-size:13px;color:var(--muted)">Contact us</span>'
        return "<form method='post' action='/billing/checkout'><input type='hidden' name='plan' value='pro'/><button class='btn btn-primary' style='width:100%' type='submit'>Subscribe</button></form>"
    def plus_btn():
        if not sub_on: return '<span style="font-size:13px;color:var(--muted)">Contact us</span>'
        return "<form method='post' action='/billing/checkout'><input type='hidden' name='plan' value='plus'/><button class='btn btn-primary' style='width:100%' type='submit'>Subscribe</button></form>"
    return f"""
<div class="pricing-grid">
  <div class="plan">
    <div class="plan-name">Free</div>
    <div class="plan-price">$0<span>/mo</span></div>
    <div class="plan-desc">Perfect for side projects &amp; prototypes</div>
    <ul>
      <li>{PLANS['free']['monthly_limit']} requests / month</li>
      <li>Full filter &amp; sort API</li>
      <li>5-min server cache</li>
      <li>ETag caching</li>
    </ul>
    <div class="plan-cta"><a href="/request-key" class="btn btn-outline" style="width:100%;justify-content:center">Get free key</a></div>
  </div>
  <div class="plan featured">
    <div class="plan-name" style="color:#60a5fa">Pro <span class="badge badge-blue" style="margin-left:6px">Popular</span></div>
    <div class="plan-price">${PLANS['pro']['price']}<span>/mo</span></div>
    <div class="plan-desc">For apps and dashboards in production</div>
    <ul>
      <li>{PLANS['pro']['monthly_limit']:,} requests / month</li>
      <li>Everything in Free</li>
      <li>Priority support</li>
      <li>Billing portal access</li>
    </ul>
    <div class="plan-cta">{pro_btn()}</div>
  </div>
  <div class="plan">
    <div class="plan-name">Plus</div>
    <div class="plan-price">${PLANS['plus']['price']}<span>/mo</span></div>
    <div class="plan-desc">High-volume or team use</div>
    <ul>
      <li>{PLANS['plus']['monthly_limit']:,} requests / month</li>
      <li>Everything in Pro</li>
      <li>Higher limits on request</li>
      <li>Team usage reporting</li>
    </ul>
    <div class="plan-cta">{plus_btn()}</div>
  </div>
</div>"""


# ---------- Playground ----------
def _playground_html() -> str:
    body = """
<style>
.pg-layout { display: grid; gap: 20px; padding: 32px 0; }
@media(min-width:860px){ .pg-layout { grid-template-columns: 1fr 1fr; } }
.pg-title { padding: 28px 0 0; }
.pg-title h1 { font-size: 24px; font-weight: 700; }
.pg-title p { color: var(--muted); margin-top: 6px; font-size: 14px; }
.pg-examples { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
.example-pill { background: var(--surface); border: 1px solid var(--border); border-radius: 99px; padding: 5px 14px; font-size: 12px; cursor: pointer; color: var(--muted); transition: all .15s; }
.example-pill:hover { border-color: var(--accent); color: var(--accent); }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.status-bar { font-size: 13px; color: var(--muted); margin: 10px 0 4px; min-height: 20px; }
.status-bar.ok { color: var(--green); }
.status-bar.err { color: #f87171; }
.result-tabs { display: flex; gap: 2px; margin-bottom: 8px; }
.tab-btn { background: transparent; border: 1px solid transparent; border-radius: 6px; padding: 5px 12px; font-size: 13px; cursor: pointer; color: var(--muted); }
.tab-btn.active { background: var(--surface); border-color: var(--border); color: var(--text); }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
</style>

<div class="wrap">
  <div class="pg-title">
    <h1>Playground</h1>
    <p>Paste a Google Sheets CSV URL and explore the API live. <a href="/faq#publish">How to publish a sheet →</a></p>
  </div>

  <div class="pg-layout">
    <div>
      <div class="card">
        <div style="margin-bottom:10px;font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">Load an example</div>
        <div class="pg-examples">
          <span class="example-pill" onclick="loadExample(1)">Products</span>
          <span class="example-pill" onclick="loadExample(2)">Employees</span>
          <span class="example-pill" onclick="loadExample(3)">Events</span>
        </div>

        <label>Google Sheets CSV URL</label>
        <input id="csv" placeholder="https://docs.google.com/.../pub?output=csv"/>

        <label>API Key <small style="text-transform:none;letter-spacing:0">(header x-api-key or ?key=) &mdash; <a href="/request-key">get one free</a></small></label>
        <input id="key" placeholder="YOUR_API_KEY"/>

        <div class="row2">
          <div>
            <label>select <small>(columns)</small></label>
            <input id="select" placeholder="name,price,status"/>
          </div>
          <div>
            <label>order</label>
            <input id="order" placeholder="-price:num"/>
          </div>
        </div>

        <div class="row2">
          <div>
            <label>limit</label>
            <input id="limit" type="number" placeholder="50"/>
          </div>
          <div>
            <label>offset</label>
            <input id="offset" type="number" placeholder="0"/>
          </div>
        </div>

        <label>filters <small>(one per line &mdash; e.g. status:active, price&gt;=10)</small></label>
        <textarea id="filters" placeholder="status:active&#10;price>=10&#10;name~widget"></textarea>

        <div style="display:flex;gap:10px;margin-top:16px">
          <button class="btn btn-primary" onclick="runFetch()">Fetch JSON</button>
          <button class="btn btn-outline" onclick="runUsage()">Check Usage</button>
        </div>
        <div class="status-bar" id="status">Ready.</div>
      </div>
    </div>

    <div>
      <div class="card" style="height:100%">
        <div class="result-tabs">
          <button class="tab-btn active" onclick="showTab('json')">JSON</button>
          <button class="tab-btn" onclick="showTab('curl')">curl</button>
          <button class="tab-btn" onclick="showTab('node')">Node</button>
          <button class="tab-btn" onclick="showTab('python')">Python</button>
        </div>
        <div id="tab-json" class="tab-panel active"><pre id="out" style="min-height:320px;max-height:600px;overflow-y:auto">Waiting for request…</pre></div>
        <div id="tab-curl" class="tab-panel"><pre id="curl-out" style="min-height:320px"># Build a request first</pre></div>
        <div id="tab-node" class="tab-panel"><pre id="node-out" style="min-height:320px">// Build a request first</pre></div>
        <div id="tab-python" class="tab-panel"><pre id="py-out" style="min-height:320px"># Build a request first</pre></div>
      </div>
    </div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
const DEMO_BASE = window.location.origin;

function loadExample(n){
  const urls = [null, DEMO_BASE+'/demo/csv/1', DEMO_BASE+'/demo/csv/2', DEMO_BASE+'/demo/csv/3'];
  const keys = [null, 'FREE_EXAMPLE_KEY_123', 'FREE_EXAMPLE_KEY_123', 'FREE_EXAMPLE_KEY_123'];
  const orders = [null, '-price:num', '-salary:num', 'date'];
  $('csv').value = urls[n]; $('key').value = keys[n]; $('order').value = orders[n];
  $('filters').value = ''; $('select').value = ''; $('limit').value = ''; $('offset').value = '';
}

function buildURL(){
  const u = new URL(window.location.origin+'/v1/fetch');
  const csv = $('csv').value.trim(); if(csv) u.searchParams.set('csv_url', csv);
  const sel = $('select').value.trim(); if(sel) u.searchParams.set('select', sel);
  const ord = $('order').value.trim(); if(ord) u.searchParams.set('order', ord);
  const lim = $('limit').value.trim(); if(lim) u.searchParams.set('limit', lim);
  const off = $('offset').value.trim(); if(off) u.searchParams.set('offset', off);
  $('filters').value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean).forEach(f=>u.searchParams.append('filter', f));
  return u;
}

function showTab(name){
  ['json','curl','node','python'].forEach(t=>{
    $('tab-'+t).classList.toggle('active', t===name);
    document.querySelectorAll('.tab-btn').forEach((b,i)=>{
      const names=['json','curl','node','python'];
      b.classList.toggle('active', names[i]===name);
    });
  });
}

function setStatus(msg, cls=''){
  const el = $('status');
  el.textContent = msg;
  el.className = 'status-bar ' + cls;
}

function buildSnippets(url, key, etag){
  const q = url.toString().replace(/"/g,'\\"');
  const h = key ? ` -H "x-api-key: ${key.replace(/"/g,'\\\\"')}"` : '';
  const etagH = etag ? ` -H "If-None-Match: ${etag}"` : '';
  $('curl-out').textContent = `curl${h}${etagH} \\\\\\n  "${q}"`;
  $('node-out').textContent = `// npm i node-fetch\\nimport fetch from 'node-fetch';\\n\\nconst res = await fetch('${q}',${key ? ` {\\n  headers: { 'x-api-key': '${key}' }\\n}` : '{}'});\\nconst data = await res.json();\\nconsole.log(data.rows);`;
  $('py-out').textContent = `import requests\\n\\nr = requests.get(\\n    '${url.origin}/v1/fetch',\\n    params=${JSON.stringify(Object.fromEntries(url.searchParams), null, 4).replace(/"([^"]+)":/g, "'$1':")},\\n    headers=${key ? `{'x-api-key': '${key}'}` : '{}'}\\n)\\nprint(r.json()['rows'])`;
}

async function runFetch(){
  setStatus('Loading…');
  const key = $('key').value.trim();
  const url = buildURL();
  try {
    const res = await fetch(url, key ? {headers:{'x-api-key':key}} : undefined);
    const etag = res.headers.get('etag');
    const text = await res.text();
    setStatus('HTTP '+res.status+(res.status<300?' ✓':' ✗'), res.status<300?'ok':'err');
    try { $('out').textContent = JSON.stringify(JSON.parse(text), null, 2); }
    catch { $('out').textContent = text; }
    buildSnippets(url, key, etag);
  } catch(e) {
    setStatus('Network error: '+e, 'err');
    $('out').textContent = String(e);
  }
}

async function runUsage(){
  const key = $('key').value.trim();
  if(!key){ setStatus('Add your API key first', 'err'); return; }
  setStatus('Loading usage…');
  try {
    const res = await fetch('/v1/usage', {headers:{'x-api-key':key}});
    const text = await res.text();
    setStatus('HTTP '+res.status, res.status<300?'ok':'err');
    try { $('out').textContent = JSON.stringify(JSON.parse(text), null, 2); }
    catch { $('out').textContent = text; }
  } catch(e) { setStatus('Error: '+e, 'err'); }
}

// Pre-fill from query string
(function(){
  const q = new URLSearchParams(location.search);
  [['csv','csv'],['key','key'],['select','select'],['order','order'],['limit','limit'],['offset','offset']].forEach(([qs,id])=>{
    const v=q.get(qs); if(v!==null) $(id).value=v;
  });
  const filters = q.getAll('filter');
  if(filters.length) $('filters').value = filters.join('\\n');
  if(q.get('autorun')==='1') runFetch();
})();
</script>
"""
    return _page("SheetsJSON — Playground", body, active="Playground")


# ---------- Examples ----------
def _examples_html() -> str:
    base = PUBLIC_BASE_URL or ""
    body = f"""
<style>
.examples-grid {{ display: grid; gap: 20px; padding: 32px 0; }}
@media(min-width:700px){{ .examples-grid {{ grid-template-columns: repeat(3,1fr); }} }}
.ex-card {{ background: var(--card); border: 1px solid var(--border); border-radius: var(--r); padding: 24px; }}
.ex-card h3 {{ font-size: 16px; font-weight: 700; margin-bottom: 6px; }}
.ex-card p {{ font-size: 13px; color: var(--muted); margin-bottom: 16px; }}
.ex-card pre {{ font-size: 11.5px; margin-bottom: 14px; }}
.ex-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
</style>
<div class="wrap" style="padding-top:32px">
  <h1 style="font-size:26px;font-weight:700">Examples</h1>
  <p style="color:var(--muted);margin-top:6px;margin-bottom:0">Live demo datasets — no sheet required. Use key <code>FREE_EXAMPLE_KEY_123</code>.</p>
  <div class="examples-grid">
    <div class="ex-card">
      <h3>Products</h3>
      <p>5 products with category, price, and status. Try filtering by status or sorting by price.</p>
      <pre><code>GET /v1/fetch
  ?csv_url={base}/demo/csv/1
  &amp;filter=status:active
  &amp;order=-price:num</code></pre>
      <div class="ex-actions">
        <a class="btn btn-primary btn-sm" href="/playground?csv={base}/demo/csv/1&key=FREE_EXAMPLE_KEY_123&order=-price:num&autorun=1">Open in Playground</a>
        <a class="btn btn-outline btn-sm" href="/v1/fetch?csv_url={base}/demo/csv/1&key=FREE_EXAMPLE_KEY_123&filter=status:active&order=-price:num" target="_blank">Raw JSON</a>
      </div>
    </div>
    <div class="ex-card">
      <h3>Employees</h3>
      <p>5 employees with role, city, and salary. Try sorting by salary or filtering by city.</p>
      <pre><code>GET /v1/fetch
  ?csv_url={base}/demo/csv/2
  &amp;filter=role:Engineer
  &amp;order=-salary:num</code></pre>
      <div class="ex-actions">
        <a class="btn btn-primary btn-sm" href="/playground?csv={base}/demo/csv/2&key=FREE_EXAMPLE_KEY_123&order=-salary:num&autorun=1">Open in Playground</a>
        <a class="btn btn-outline btn-sm" href="/v1/fetch?csv_url={base}/demo/csv/2&key=FREE_EXAMPLE_KEY_123&order=-salary:num" target="_blank">Raw JSON</a>
      </div>
    </div>
    <div class="ex-card">
      <h3>Events</h3>
      <p>4 events with date, city, seats, and status. Filter by open events or order by date.</p>
      <pre><code>GET /v1/fetch
  ?csv_url={base}/demo/csv/3
  &amp;filter=status:open
  &amp;order=date</code></pre>
      <div class="ex-actions">
        <a class="btn btn-primary btn-sm" href="/playground?csv={base}/demo/csv/3&key=FREE_EXAMPLE_KEY_123&filter=status:open&autorun=1">Open in Playground</a>
        <a class="btn btn-outline btn-sm" href="/v1/fetch?csv_url={base}/demo/csv/3&key=FREE_EXAMPLE_KEY_123&filter=status:open" target="_blank">Raw JSON</a>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:32px">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:16px">Filter syntax reference</h2>
    <table>
      <thead><tr><th>Operator</th><th>Syntax</th><th>Example</th></tr></thead>
      <tbody>
        <tr><td>Exact match</td><td><code>col:value</code></td><td><code>filter=status:active</code></td></tr>
        <tr><td>Not equal</td><td><code>col!=value</code></td><td><code>filter=city!=Remote</code></td></tr>
        <tr><td>Contains</td><td><code>col~value</code></td><td><code>filter=name~ali</code></td></tr>
        <tr><td>Starts with</td><td><code>col^value</code></td><td><code>filter=name^A</code></td></tr>
        <tr><td>Ends with</td><td><code>col$value</code></td><td><code>filter=email$@gmail.com</code></td></tr>
        <tr><td>Numeric &gt; &lt; &gt;= &lt;=</td><td><code>col&gt;=n</code></td><td><code>filter=price&gt;=10</code></td></tr>
      </tbody>
    </table>
    <hr class="divider"/>
    <p style="font-size:13px;color:var(--muted)"><strong style="color:var(--text)">order</strong> — string: <code>order=name</code> &nbsp; numeric: <code>order=price:num</code> &nbsp; descending: prefix <code>-</code> e.g. <code>order=-price:num</code></p>
  </div>
</div>
"""
    return _page("SheetsJSON — Examples", body, active="Examples")


# ---------- Pricing ----------
def _pricing_html() -> str:
    body = f"""
<div class="wrap" style="padding:40px 0">
  <h1 style="font-size:30px;font-weight:800;text-align:center;margin-bottom:10px">Simple pricing</h1>
  <p style="text-align:center;color:var(--muted);margin-bottom:40px">Start free. Upgrade when you need more. Cancel anytime.</p>
  {_pricing_cards()}

  <div class="card" style="margin-top:48px">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:20px">API Quick Reference</h2>
    <p style="margin-bottom:12px"><strong>Endpoint:</strong> <code>GET /v1/fetch</code></p>
    <p style="margin-bottom:12px"><strong>Auth:</strong> <code>x-api-key: YOUR_KEY</code> header or <code>?key=YOUR_KEY</code> query param</p>
    <p style="margin-bottom:12px"><strong>Required param:</strong> <code>csv_url</code> — Google Sheets <em>Publish to web &rarr; CSV</em> link</p>
    <hr class="divider"/>
    <table>
      <thead><tr><th>Parameter</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><code>csv_url</code></td><td>string</td><td>Google Sheets published CSV URL (required)</td></tr>
        <tr><td><code>filter</code></td><td>string (repeatable)</td><td><code>col:v</code> <code>col!=v</code> <code>col~v</code> <code>col^v</code> <code>col$v</code> <code>col&gt;=n</code></td></tr>
        <tr><td><code>order</code></td><td>string</td><td><code>col</code> or <code>col:num</code>, prefix <code>-</code> for desc</td></tr>
        <tr><td><code>select</code></td><td>string</td><td>Comma-separated columns to return</td></tr>
        <tr><td><code>limit</code></td><td>integer</td><td>Max rows (1–10000)</td></tr>
        <tr><td><code>offset</code></td><td>integer</td><td>Rows to skip</td></tr>
        <tr><td><code>cache_bypass</code></td><td>0 or 1</td><td>Force refetch from Google</td></tr>
      </tbody>
    </table>
    <hr class="divider"/>
    <div style="display:grid;gap:14px">
      <div>
        <div style="font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">curl</div>
        <pre><code>curl -H "x-api-key: YOUR_KEY" \\
  "{PUBLIC_BASE_URL}/v1/fetch?csv_url=YOUR_SHEET_URL&filter=status:active&order=-price:num&limit=50"</code></pre>
      </div>
      <div>
        <div style="font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Node / Fetch</div>
        <pre><code>const res = await fetch('{PUBLIC_BASE_URL}/v1/fetch?csv_url=YOUR_SHEET_URL', {{
  headers: {{ 'x-api-key': 'YOUR_KEY' }}
}});
const {{ rows }} = await res.json();</code></pre>
      </div>
      <div>
        <div style="font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Python</div>
        <pre><code>import requests
r = requests.get('{PUBLIC_BASE_URL}/v1/fetch',
    params={{'csv_url': 'YOUR_SHEET_URL', 'filter': 'status:active'}},
    headers={{'x-api-key': 'YOUR_KEY'}})
print(r.json()['rows'])</code></pre>
      </div>
    </div>
  </div>
</div>
"""
    return _page("SheetsJSON — Pricing & Docs", body, active="Pricing")


# ---------- Request Key ----------
def _request_key_html() -> str:
    body = f"""
<div class="wrap-sm" style="padding:40px 0">
  <h1 style="font-size:26px;font-weight:700;margin-bottom:6px">Get your API key</h1>
  <p style="color:var(--muted);margin-bottom:28px">Free keys are issued instantly. Pro/Plus — use the <a href="/pricing">pricing page</a> to subscribe.</p>
  <div class="card">
    <form method="post" action="/request-key">
      <label>Your Name</label>
      <input name="name" required autocomplete="name" placeholder="Ada Lovelace"/>
      <label>Email</label>
      <input name="email" type="email" required autocomplete="email" placeholder="you@example.com"/>
      <label>Plan</label>
      <select name="plan">
        <option value="free">Free &mdash; {PLANS['free']['monthly_limit']} requests / month (free)</option>
        <option value="pro">Pro &mdash; {PLANS['pro']['monthly_limit']:,} requests / month (${PLANS['pro']['price']}/mo via Stripe)</option>
        <option value="plus">Plus &mdash; {PLANS['plus']['monthly_limit']:,} requests / month (${PLANS['plus']['price']}/mo via Stripe)</option>
      </select>
      <label>What will you use it for? <small style="text-transform:none;letter-spacing:0">(optional)</small></label>
      <textarea name="use_case" placeholder="e.g. Powering a product table on my Webflow site"></textarea>
      <input name="company" style="display:none" autocomplete="off"/>
      <div style="margin-top:20px"><button class="btn btn-primary" type="submit" style="width:100%;justify-content:center">Get my key</button></div>
    </form>
  </div>
  <p style="text-align:center;margin-top:16px;font-size:13px;color:var(--muted)">Need more? <a href="/pricing">See Pro &amp; Plus plans &rarr;</a></p>
</div>
"""
    return _page("SheetsJSON — Get API Key", body)


def _key_issued_html(plan: str, key_text: Optional[str]) -> str:
    if key_text:
        content = f"""
<div class="alert alert-success" style="margin-bottom:20px">Your API key is ready.</div>
<div class="key-box">{key_text}</div>
<p style="font-size:13px;color:var(--muted);margin-top:12px">
  Plan: <strong style="color:var(--text)">{PLANS.get(plan,{}).get('label', plan)}</strong> &mdash;
  {PLANS.get(plan,{}).get('monthly_limit',0):,} requests / month.<br/>
  Pass it as header <code>x-api-key: {key_text[:12]}…</code> or query <code>?key=…</code>
</p>
<div style="display:flex;gap:10px;margin-top:20px;flex-wrap:wrap">
  <a class="btn btn-primary" href="/playground?key={key_text}">Open Playground &rarr;</a>
  <a class="btn btn-outline" href="/pricing">API Docs</a>
</div>"""
    else:
        content = "<p>Thanks! We'll email your key shortly.</p>"
    body = f'<div class="wrap-sm" style="padding:40px 0"><div class="card"><h1 style="font-size:22px;font-weight:700;margin-bottom:20px">Your key is ready</h1>{content}</div></div>'
    return _page("SheetsJSON — Key Issued", body)


# ---------- Usage ----------
def _usage_html() -> str:
    body = """
<div class="wrap-sm" style="padding:40px 0">
  <h1 style="font-size:26px;font-weight:700;margin-bottom:6px">Check Usage</h1>
  <p style="color:var(--muted);margin-bottom:28px">See how many requests you've used this month.</p>
  <div class="card">
    <label>API Key</label>
    <input id="key" placeholder="YOUR_API_KEY" autocomplete="off"/>
    <div style="margin-top:14px"><button class="btn btn-primary" onclick="checkUsage()">Check Usage</button></div>
  </div>
  <div id="result" style="margin-top:16px;display:none" class="card">
    <div id="result-content"></div>
  </div>
</div>
<script>
async function checkUsage(){
  const key = document.getElementById('key').value.trim();
  if(!key){ alert('Enter an API key first'); return; }
  try {
    const res = await fetch('/v1/usage', {headers:{'x-api-key':key}});
    const data = await res.json();
    if(!res.ok){ showResult('<div class="alert" style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:#fca5a5;padding:14px 18px;border-radius:8px">'+JSON.stringify(data)+'</div>'); return; }
    const pct = Math.min(100, Math.round((data.used/data.limit)*100));
    const color = pct>90?'#ef4444':pct>70?'#f59e0b':'var(--green)';
    showResult(`
      <div style="display:flex;justify-content:space-between;margin-bottom:12px">
        <span><strong>${data.plan}</strong> plan</span>
        <span style="color:var(--muted)">${data.period}</span>
      </div>
      <div style="font-size:28px;font-weight:800;margin-bottom:4px">${data.used.toLocaleString()} <span style="font-size:15px;font-weight:400;color:var(--muted)">/ ${data.limit.toLocaleString()}</span></div>
      <div style="font-size:13px;color:var(--muted);margin-bottom:14px">requests used this month</div>
      <div style="background:var(--surface);border-radius:99px;height:8px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:${color};border-radius:99px;transition:width .4s"></div>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-top:6px">${pct}% used</div>
    `);
  } catch(e) { showResult('<p style="color:#f87171">Error: '+e+'</p>'); }
}
function showResult(html){
  const r = document.getElementById('result');
  document.getElementById('result-content').innerHTML = html;
  r.style.display='block';
}
</script>
"""
    return _page("SheetsJSON — Usage", body)


# ---------- FAQ ----------
def _faq_html() -> str:
    faqs = [
        ("What links are allowed?",
         "Only published Google Sheets CSV links. In your sheet: <strong>File → Share → Publish to web</strong>, select your tab, choose <strong>CSV</strong>, and click Publish. The URL must contain <code>/pub</code> and <code>output=csv</code>."),
        ("How do filters work?",
         "Use the <code>filter</code> query param (repeatable). Operators: <code>col:value</code> (exact), <code>col!=v</code> (not equal), <code>col~v</code> (contains), <code>col^v</code> (starts with), <code>col$v</code> (ends with). Numeric: <code>col&gt;=n</code>, <code>col&lt;=n</code>, <code>col&gt;n</code>, <code>col&lt;n</code>. Comparisons handle <code>$</code>, <code>%</code>, and comma-formatted numbers."),
        ("How does sorting work?",
         "Use <code>order=col</code> for alphabetical sort, <code>order=col:num</code> for numeric. Prefix with <code>-</code> for descending: <code>order=-price:num</code>."),
        ("Is there caching?",
         "Yes. The server caches each CSV for 5 minutes (configurable via <code>CACHE_TTL_SECONDS</code>). Responses include an <code>ETag</code> header — send <code>If-None-Match</code> on repeat requests and get a <code>304 Not Modified</code> with no body."),
        ("Do you store my spreadsheet data?",
         "No. Sheet content is only held in memory for the cache TTL (max 5 minutes), then discarded. We persist API keys and monthly usage counts only. See our <a href='/privacy'>Privacy Policy</a>."),
        ("What are the rate limits?",
         f"90 requests per minute per API key or IP. Monthly limits: Free {PLANS['free']['monthly_limit']}, Pro {PLANS['pro']['monthly_limit']:,}, Plus {PLANS['plus']['monthly_limit']:,}."),
        ("How do I embed a table in my website?",
         "Use the <code>/embed</code> page to generate a snippet. Drop the <code>&lt;script&gt;</code> tag and a <code>&lt;div data-csv=&quot;...&quot;&gt;</code> element into any HTML page. The table renders client-side with search, sort, and pagination — no iframe needed."),
        ("Can I cancel my subscription?",
         "Yes. Use the billing portal (linked from your success page after subscribing) to cancel anytime. Your key downgrades to the Free plan at the end of the billing period."),
    ]
    items = ""
    for q, a in faqs:
        items += f"""
<div style="border-bottom:1px solid var(--border);padding:20px 0">
  <h3 style="font-size:15px;font-weight:600;margin-bottom:8px">{q}</h3>
  <p style="font-size:14px;color:var(--muted);line-height:1.7">{a}</p>
</div>"""
    body = f'<div class="wrap-sm" style="padding:40px 0"><h1 style="font-size:26px;font-weight:700;margin-bottom:28px">FAQ</h1>{items}</div>'
    return _page("SheetsJSON — FAQ", body, active="FAQ")


# ---------- Privacy ----------
PRIVACY_HTML = """
<div class="wrap-sm" style="padding:40px 0">
  <h1 style="font-size:26px;font-weight:700;margin-bottom:6px">Privacy Policy</h1>
  <p style="color:var(--muted);margin-bottom:28px">Last updated: 2025.</p>
  <div class="card" style="line-height:1.8">
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">What we collect</h2>
    <ul style="color:var(--muted);font-size:14px;padding-left:20px;margin-bottom:20px">
      <li>API keys (randomly generated UUIDs) and their associated plan and monthly usage count.</li>
      <li>Email address and name, only when you request a key or subscribe.</li>
      <li>Stripe handles all payment data — we never see raw card numbers.</li>
    </ul>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">What we do NOT collect</h2>
    <ul style="color:var(--muted);font-size:14px;padding-left:20px;margin-bottom:20px">
      <li>Your spreadsheet content. CSV data is cached in memory for up to 5 minutes and never written to disk or a database.</li>
      <li>Request payloads or query parameters beyond what is needed for rate limiting.</li>
    </ul>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Data retention</h2>
    <p style="color:var(--muted);font-size:14px;margin-bottom:20px">Usage counters reset each calendar month. API keys are retained until revoked. Email addresses are retained only as long as your subscription is active.</p>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Third parties</h2>
    <p style="color:var(--muted);font-size:14px">Stripe for payments. Optional: Plausible Analytics (privacy-friendly, no cookies). We do not sell or share your data.</p>
  </div>
</div>
"""

TERMS_HTML = """
<div class="wrap-sm" style="padding:40px 0">
  <h1 style="font-size:26px;font-weight:700;margin-bottom:6px">Terms of Service</h1>
  <p style="color:var(--muted);margin-bottom:28px">Last updated: 2025.</p>
  <div class="card" style="line-height:1.8">
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Acceptable use</h2>
    <p style="color:var(--muted);font-size:14px;margin-bottom:16px">You may use SheetsJSON for lawful purposes. You may not use it to scrape, spam, distribute malware, or circumvent access controls on third-party systems.</p>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Rate limits &amp; quotas</h2>
    <p style="color:var(--muted);font-size:14px;margin-bottom:16px">Exceeding your monthly quota returns HTTP 429. Persistent abuse may result in key revocation without refund.</p>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Uptime &amp; liability</h2>
    <p style="color:var(--muted);font-size:14px;margin-bottom:16px">Service is provided as-is. We make reasonable efforts for uptime but do not guarantee SLA. We are not liable for data loss or downstream outages.</p>
    <h2 style="font-size:16px;font-weight:700;margin-bottom:8px">Changes</h2>
    <p style="color:var(--muted);font-size:14px">We may update these terms. Continued use after changes constitutes acceptance.</p>
  </div>
</div>
"""

def _wrap_static(html_body: str, title: str) -> str:
    return _page(title, html_body)

# ---------- Embed generator ----------
def _embed_generator_html() -> str:
    base = PUBLIC_BASE_URL or ""
    body = f"""
<div class="wrap-sm" style="padding:40px 0">
  <h1 style="font-size:26px;font-weight:700;margin-bottom:6px">Embed a Sheet as a table</h1>
  <p style="color:var(--muted);margin-bottom:28px">Generate a snippet and paste it into Webflow, Framer, or any HTML page.</p>
  <div class="card">
    <label>Published CSV URL</label>
    <input id="csv" placeholder="https://docs.google.com/.../pub?output=csv"/>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div><label>API Key</label><input id="ekey" placeholder="YOUR_API_KEY"/></div>
      <div><label>Page size</label><input id="page" type="number" value="10"/></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div><label>Select columns</label><input id="sel" placeholder="name,price,status"/></div>
      <div><label>Default order</label><input id="ord" placeholder="-price:num"/></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div><label>Theme</label>
        <select id="theme"><option>auto</option><option>light</option><option>dark</option></select>
      </div>
      <div><label>Max rows to fetch</label><input id="maxrows" type="number" value="500"/></div>
    </div>
    <label>Filters <small style="text-transform:none;letter-spacing:0">(separate with ;)</small></label>
    <input id="filters" placeholder="status:active;price>=10"/>
    <div style="margin-top:16px"><button class="btn btn-primary" onclick="genSnippet()">Generate snippet</button></div>
  </div>
  <div class="card" style="margin-top:16px">
    <label>Your snippet</label>
    <pre id="snippet-out" style="min-height:80px">&lt;!-- fill the form and click Generate --&gt;</pre>
    <button class="btn btn-outline btn-sm" style="margin-top:8px" onclick="copySnippet()">Copy to clipboard</button>
  </div>
</div>
<script>
function genSnippet(){{
  const csv=document.getElementById('csv').value.trim();
  if(!csv){{document.getElementById('snippet-out').textContent='// Add a CSV URL first'; return;}}
  const attrs=[];
  attrs.push(`data-csv="${{csv.replace(/"/g,'&quot;')}}"`);
  const key=document.getElementById('ekey').value.trim(); if(key) attrs.push(`data-key="${{key}}"`);
  const sel=document.getElementById('sel').value.trim(); if(sel) attrs.push(`data-select="${{sel}}"`);
  const ord=document.getElementById('ord').value.trim(); if(ord) attrs.push(`data-order="${{ord}}"`);
  const fil=document.getElementById('filters').value.trim(); if(fil) attrs.push(`data-filters="${{fil}}"`);
  const page=document.getElementById('page').value.trim(); if(page) attrs.push(`data-page="${{page}}"`);
  const mr=document.getElementById('maxrows').value.trim(); if(mr) attrs.push(`data-limit="${{mr}}"`);
  const theme=document.getElementById('theme').value.trim(); if(theme) attrs.push(`data-theme="${{theme}}"`);
  const div=`<div class="sj-table" ${{attrs.join(' ')}}></div>`;
  const scr=`<script src="{base}/embed.js" async><\\/script>`;
  document.getElementById('snippet-out').textContent=div+'\\n'+scr;
}}
function copySnippet(){{
  const text=document.getElementById('snippet-out').textContent;
  navigator.clipboard.writeText(text).then(()=>alert('Copied!')).catch(()=>{{
    const el=document.createElement('textarea'); el.value=text; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el); alert('Copied!');
  }});
}}
</script>
"""
    return _page("SheetsJSON — Embed Generator", body)


# ---------- Embeddable JS ----------
_EMBED_JS = r"""
(function(){
  'use strict';
  function onReady(fn){ if(document.readyState!=='loading'){fn()} else {document.addEventListener('DOMContentLoaded', fn);} }
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  function toNum(v){
    if(v==null) return null;
    let t=String(v).trim();
    if(!t) return null;
    if(t[0]==='$') t=t.slice(1);
    const pct=t.endsWith('%'); if(pct) t=t.slice(0,-1);
    t=t.replace(/[,\s]/g,'');
    const n=parseFloat(t);
    if(!isFinite(n)) return null;
    return pct?n/100:n;
  }
  function ensureStyles(){
    if(document.getElementById('sj-embed-css')) return;
    const css=`.sj-wrap{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto;color:#eaf0ff}
.sj-theme-light .sj-wrap{color:#0c1633}
.sj-box{background:#0e1630;border:1px solid #233366;border-radius:12px;padding:10px;overflow:auto}
.sj-theme-light .sj-box{background:#f7f9ff;border-color:#d6e0ff}
.sj-controls{display:flex;gap:8px;align-items:center;margin:6px 0 10px}
.sj-search{flex:1 1 auto;padding:8px 10px;border-radius:8px;border:1px solid #26335f;background:#0a0f24;color:inherit}
.sj-theme-light .sj-search{background:#fff;border-color:#ccd6ff}
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
.sj-loading,.sj-error{padding:8px 10px}`;
    const el=document.createElement('style'); el.id='sj-embed-css'; el.textContent=css; document.head.appendChild(el);
  }
  function scriptOrigin(){
    const cand=document.currentScript||document.querySelector('script[src*="/embed.js"]');
    try{ return cand?(new URL(cand.src)).origin:window.location.origin; } catch(e){ return window.location.origin; }
  }
  function initContainer(container){
    const d=container.dataset;
    const csv=(d.csv||'').trim();
    if(!csv){ container.innerHTML="<div class='sj-error'>Missing <code>data-csv</code></div>"; return; }
    const key=(d.key||'').trim();
    const select=(d.select||'').trim();
    const order=(d.order||'').trim();
    const filters=(d.filters||'').trim();
    const pageSize=Math.max(1,parseInt(d.page||'10',10));
    const limit=Math.max(pageSize,parseInt(d.limit||'500',10));
    const theme=(d.theme||'auto');
    ensureStyles();
    const wrap=document.createElement('div');
    wrap.className='sj-wrap '+(theme==='dark'?'sj-theme-dark':(theme==='light'?'sj-theme-light':(matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches?'sj-theme-dark':'sj-theme-light')));
    const box=document.createElement('div'); box.className='sj-box';
    const controls=document.createElement('div'); controls.className='sj-controls';
    const search=document.createElement('input'); search.className='sj-search'; search.placeholder='Search…'; search.setAttribute('aria-label','Search');
    controls.appendChild(search);
    const table=document.createElement('table'); table.className='sj-table-el';
    const thead=document.createElement('thead'); const tbody=document.createElement('tbody');
    table.appendChild(thead); table.appendChild(tbody);
    const pager=document.createElement('div'); pager.className='sj-pager';
    const prev=document.createElement('button'); prev.className='sj-btn'; prev.textContent='Prev';
    const next=document.createElement('button'); next.className='sj-btn'; next.textContent='Next';
    const info=document.createElement('span'); info.className='sj-small';
    pager.appendChild(prev); pager.appendChild(next); pager.appendChild(info);
    box.appendChild(controls); box.appendChild(table); box.appendChild(pager);
    container.innerHTML=''; container.appendChild(wrap); wrap.appendChild(box);
    let rows=[]; let view=[]; let cols=[]; let sortCol=null; let sortDir=1; let sortNumeric=false; let page=1;
    function setInfo(){ const total=view.length; const pages=Math.max(1,Math.ceil(total/pageSize)); if(page>pages) page=pages; info.textContent=total?("Page "+page+" / "+pages+" • "+total+" rows"):"No rows"; prev.disabled=(page<=1); next.disabled=(page>=pages); }
    function detectNumeric(col){ for(const r of view){ const v=toNum(r[col]); if(v!=null) return true; } return false; }
    function renderHead(){ const tr=document.createElement('tr'); cols.forEach(c=>{ const th=document.createElement('th'); th.className='sj-th'; th.textContent=c; const s=document.createElement('span'); s.className='sj-sort'; s.textContent=c===sortCol?(sortDir>0?'▲':'▼'):'↕'; th.appendChild(s); th.addEventListener('click',()=>{ if(sortCol===c){ sortDir=-sortDir; } else { sortCol=c; sortDir=1; sortNumeric=detectNumeric(c); } sortView(); renderBody(); renderHead(); }); tr.appendChild(th); }); thead.innerHTML=''; thead.appendChild(tr); }
    function sortView(){ if(!sortCol){ setInfo(); return; } view.sort((a,b)=>{ let av=a[sortCol],bv=b[sortCol]; if(sortNumeric){ av=toNum(av)??-Infinity; bv=toNum(bv)??-Infinity; } else { av=(av||'').toLowerCase(); bv=(bv||'').toLowerCase(); } return av<bv?-sortDir:av>bv?sortDir:0; }); setInfo(); }
    function rowMatchesSearch(r,q){ if(!q) return true; const lq=q.toLowerCase(); return Object.values(r).some(v=>String(v||'').toLowerCase().includes(lq)); }
    function renderBody(){ const start=(page-1)*pageSize; const end=Math.min(start+pageSize,view.length); const frag=document.createDocumentFragment(); for(let i=start;i<end;i++){ const r=view[i]; const tr=document.createElement('tr'); cols.forEach(c=>{ const td=document.createElement('td'); td.className='sj-td'; td.innerHTML=esc(r[c]??''); tr.appendChild(td); }); frag.appendChild(tr); } tbody.innerHTML=''; tbody.appendChild(frag); setInfo(); }
    search.addEventListener('input',()=>{ const q=search.value.trim(); view=rows.filter(r=>rowMatchesSearch(r,q)); sortView(); page=1; renderBody(); });
    prev.addEventListener('click',()=>{ if(page>1){ page--; renderBody(); } });
    next.addEventListener('click',()=>{ const pages=Math.max(1,Math.ceil(view.length/pageSize)); if(page<pages){ page++; renderBody(); } });
    (async function(){
      const base=scriptOrigin();
      const u=new URL(base+"/v1/fetch");
      u.searchParams.set("csv_url",csv);
      if(select) u.searchParams.set("select",select);
      if(order) u.searchParams.set("order",order);
      if(limit) u.searchParams.set("limit",String(limit));
      if(filters){ filters.split(';').map(s=>s.trim()).filter(Boolean).forEach(f=>u.searchParams.append("filter",f)); }
      box.insertAdjacentHTML('afterbegin',"<div class='sj-loading'>Loading…</div>");
      const loadingEl=box.querySelector('.sj-loading');
      try{
        const headers=key?{"x-api-key":key}:{};
        const res=await fetch(u.toString(),{headers});
        const text=await res.text();
        if(!res.ok){ throw new Error("HTTP "+res.status+" "+text); }
        let data; try{ data=JSON.parse(text); } catch{ data={rows:[]}; }
        rows=(data&&(data.rows||data.data))||[];
        if(select){ cols=select.split(',').map(s=>s.trim()).filter(Boolean); } else { cols=rows.length?Object.keys(rows[0]):[]; }
        if(order){ let o=order.trim(); sortDir=1; if(o.startsWith('-')){ sortDir=-1; o=o.slice(1); } if(o.endsWith(':num')){ sortNumeric=true; o=o.slice(0,-4); } else { sortNumeric=false; } sortCol=o; }
        view=rows.slice(0);
        sortView(); renderHead(); renderBody();
      } catch(e){ container.innerHTML="<div class='sj-error'>"+esc(e.message||String(e))+"</div>"; }
      finally{ if(loadingEl&&loadingEl.remove) loadingEl.remove(); }
    })();
  }
  onReady(function(){ document.querySelectorAll('.sj-table,[data-csv]').forEach(initContainer); });
})();
"""


# =============================================================================
# DEMO CSV ENDPOINTS
# =============================================================================
@app.get("/demo/csv/1", response_class=PlainTextResponse)
def demo_csv_1():
    return PlainTextResponse("id,name,category,price,status\n1,Widget A,Gadgets,19.99,active\n2,Widget B,Gadgets,24.50,active\n3,Thing C,Tools,8.00,archived\n4,Thing D,Tools,12.25,active\n5,Gizmo E,Accessories,5.50,active\n", media_type="text/csv")

@app.get("/demo/csv/2", response_class=PlainTextResponse)
def demo_csv_2():
    return PlainTextResponse("id,name,role,city,salary\n101,Alice Johnson,Engineer,Denver,115000\n102,Bob Smith,Designer,Austin,98000\n103,Carla Reyes,Engineer,NYC,142000\n104,David Kim,Support,Remote,70000\n105,Erin Patel,PM,NYC,128000\n", media_type="text/csv")

@app.get("/demo/csv/3", response_class=PlainTextResponse)
def demo_csv_3():
    return PlainTextResponse("date,title,city,seats,status\n2025-08-01,Launch Party,New York,120,open\n2025-08-05,Webinar: Sheets to JSON,Online,500,open\n2025-08-10,Meetup,Denver,80,waitlist\n2025-08-15,Workshop,Austin,40,cancelled\n", media_type="text/csv")


# =============================================================================
# ROUTES — PAGES
# =============================================================================
@app.get("/", response_class=HTMLResponse, tags=["Pages"])
def home(): return HTMLResponse(_home_html())

@app.get("/playground", response_class=HTMLResponse, tags=["Pages"])
def playground(): return HTMLResponse(_playground_html())

@app.get("/examples", response_class=HTMLResponse, tags=["Pages"])
def examples_page(): return HTMLResponse(_examples_html())

@app.get("/pricing", response_class=HTMLResponse, tags=["Pages"])
def pricing(): return HTMLResponse(_pricing_html())

@app.get("/request-key", response_class=HTMLResponse, tags=["Pages"])
def request_key_form(): return HTMLResponse(_request_key_html())

@app.get("/usage", response_class=HTMLResponse, tags=["Pages"])
def usage_page(): return HTMLResponse(_usage_html())

@app.get("/faq", response_class=HTMLResponse, tags=["Pages"])
def faq_page(): return HTMLResponse(_faq_html())

@app.get("/privacy", response_class=HTMLResponse, tags=["Pages"])
def privacy_page(): return HTMLResponse(_wrap_static(PRIVACY_HTML, "SheetsJSON — Privacy Policy"))

@app.get("/terms", response_class=HTMLResponse, tags=["Pages"])
def terms_page(): return HTMLResponse(_wrap_static(TERMS_HTML, "SheetsJSON — Terms of Service"))

@app.get("/embed", response_class=HTMLResponse, tags=["Pages"])
def embed_generator(): return HTMLResponse(_embed_generator_html())

@app.get("/embed.js", tags=["Pages"])
def embed_js(): return FastAPIResponse(content=_EMBED_JS, media_type="application/javascript")


# =============================================================================
# KEY REQUEST (POST)
# =============================================================================
@app.post("/request-key", tags=["Pages"])
async def request_key_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    plan: str = Form("free"),
    use_case: str = Form(""),
    company: str = Form(""),  # honeypot
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
    return HTMLResponse(_key_issued_html(payload["plan"], key_text))


# =============================================================================
# SEO
# =============================================================================
@app.get("/robots.txt", response_class=PlainTextResponse, tags=["SEO"])
def robots(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n")

@app.get("/sitemap.xml", tags=["SEO"])
def sitemap(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    urls = ["/", "/playground", "/examples", "/pricing", "/usage", "/faq", "/privacy", "/terms"]
    items = "".join(f"<url><loc>{base}{p}</loc></url>" for p in urls)
    return FastAPIResponse(
        content=f"<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{items}</urlset>",
        media_type="application/xml"
    )

@app.get("/healthz")
def healthz(): return {"ok": True, "version": "1.0.0"}


# =============================================================================
# API
# =============================================================================
@app.get("/v1/fetch", tags=["API"], summary="Fetch rows from a published Google Sheet as JSON")
def fetch(
    request: Request, response: Response,
    csv_url: str = Query(..., description="Google Sheets Publish-to-web CSV URL"),
    select: Optional[str] = Query(None, description="Comma-separated columns to return"),
    filter: Optional[List[str]] = Query(None, description="Filter expressions (repeatable)"),
    order: Optional[str] = Query(None, description="Sort column, e.g. -price:num"),
    limit: Optional[int] = Query(None, ge=1, le=10000),
    offset: Optional[int] = Query(0, ge=0),
    cache_bypass: Optional[int] = Query(0),
    api_key_header: Optional[str] = Header(None, alias="x-api-key"),
    key: Optional[str] = Query(None),
):
    api_key = require_and_track_key(api_key_header, key)
    rl_or_429(request, api_key)
    validate_csv_url(csv_url)
    rows, raw_sha = fetch_csv_rows(csv_url, bypass_cache=bool(cache_bypass))
    data = apply_filters(rows, select=select, filters=filter, order=order, limit=limit, offset=offset)

    qnorm = json.dumps({"select": select, "filter": filter, "order": order, "limit": limit, "offset": offset}, sort_keys=True, separators=(",", ":"))
    etag = hashlib.sha1((raw_sha + "|" + qnorm + "|" + str(len(data))).encode()).hexdigest()
    response.headers["ETag"] = etag
    if (request.headers.get("if-none-match") or "") == etag:
        return Response(status_code=304)

    body = {
        "rows": data,
        "meta": {
            "total_rows": len(rows),
            "returned": len(data),
            "cached_seconds_left": max(0, CACHE_TTL - int(time.time() - _cache.get(csv_url, {}).get("ts", 0))),
            "cache_ttl_seconds": CACHE_TTL,
            "api_key": api_key if REQUIRE_API_KEY else None,
            "etag": etag,
        }
    }
    return JSONResponse(content=body, headers={"ETag": etag})


@app.get("/v1/usage", tags=["Account"], summary="Get usage stats for your API key")
def api_usage(
    api_key_header: Optional[str] = Header(None, alias="x-api-key"),
    key: Optional[str] = Query(None),
):
    if not REQUIRE_API_KEY:
        return {"message": "API key requirement is disabled."}
    api_key = api_key_header or key
    if not api_key or get_limit_for_key(api_key) <= 0:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    plan = get_plan_for_key(api_key)
    return {
        "api_key": api_key,
        "plan": plan,
        "period": current_period(),
        "used": get_usage(api_key),
        "limit": get_limit_for_key(api_key),
    }


# =============================================================================
# ADMIN
# =============================================================================
security = HTTPBasic()

def admin_guard(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    p_ok = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return True

@app.get("/admin/keys", tags=["Admin"])
def admin_keys_page(auth: bool = Depends(admin_guard)):
    if KEYS_BACKEND == "db":
        items = keys_db_list(1000)
    else:
        items = [{"api_key": k, "plan": v.get("plan","?"), "monthly_limit": v.get("monthly_limit","?"), "created_at":"(file)"} for k,v in load_keys_file().items()]
    rows_html = ""
    for item in items:
        k = item["api_key"]; plan = item["plan"]; lim = item["monthly_limit"]
        rows_html += (
            f"<tr><td><code style='font-size:12px'>{k}</code></td><td>{plan}</td><td>{lim}</td><td>"
            f"<form method='post' action='/admin/keys/update' style='display:inline'>"
            f"<input type='hidden' name='api_key' value='{k}'/>"
            f"<select name='plan' style='width:auto;padding:4px 8px;font-size:12px'>"
            f"<option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select>"
            f" <input name='monthly_limit' type='number' placeholder='limit' style='width:90px;padding:4px 8px;font-size:12px'/>"
            f" <button class='btn btn-outline btn-sm' type='submit'>Update</button></form>"
            f" <form method='post' action='/admin/keys/revoke' style='display:inline;margin-left:6px'>"
            f"<input type='hidden' name='api_key' value='{k}'/><button class='btn btn-danger btn-sm' type='submit'>Revoke</button></form>"
            f"</td></tr>"
        )
    if not rows_html:
        rows_html = "<tr><td colspan='4' style='color:var(--muted)'>No keys yet.</td></tr>"
    html = _page("Admin — SheetsJSON", f"""
<div class="wrap" style="padding:32px 0">
  <h1 style="font-size:22px;font-weight:700;margin-bottom:20px">Admin — API Keys</h1>
  <div class="card" style="margin-bottom:16px">
    <strong>Mint new key:</strong>
    <form method='post' action='/admin/keys/mint' style='display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;align-items:flex-end'>
      <div><label>Plan</label><select name='plan' style='width:auto;padding:8px 12px'><option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select></div>
      <div><label>Monthly limit</label><input name='monthly_limit' type='number' placeholder='(plan default)' style='width:160px'/></div>
      <button class='btn btn-primary' type='submit'>Create key</button>
    </form>
  </div>
  <div class="card">
    <table>
      <thead><tr><th>API Key</th><th>Plan</th><th>Monthly Limit</th><th>Actions</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
""")
    return HTMLResponse(html)

@app.post("/admin/keys/mint", tags=["Admin"])
def admin_mint_key(plan: str = Form("free"), monthly_limit: Optional[int] = Form(None), auth: bool = Depends(admin_guard)):
    k = issue_key(plan, monthly_limit)
    return PlainTextResponse(f"Created: {k}\n\nBack: /admin/keys")

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
    return RedirectResponse("/admin/keys", status_code=303)

@app.post("/admin/keys/revoke", tags=["Admin"])
def admin_revoke_key(api_key: str = Form(...), auth: bool = Depends(admin_guard)):
    if KEYS_BACKEND == "db":
        keys_db_delete(api_key)
    else:
        keys = load_keys_file()
        if api_key in keys:
            del keys[api_key]
            save_keys_file(keys)
    return RedirectResponse("/admin/keys", status_code=303)


# =============================================================================
# BILLING (STRIPE)
# =============================================================================
def orders_insert(session_id, email, plan, api_key, status, customer_id=None, subscription_id=None):
    with db_conn() as con:
        cur = con.cursor()
        if DB_IS_PG:
            q = """INSERT INTO orders(session_id,email,plan,api_key,status,created_at,customer_id,subscription_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (session_id) DO UPDATE SET
                     email=EXCLUDED.email, plan=EXCLUDED.plan,
                     api_key=COALESCE(orders.api_key, EXCLUDED.api_key),
                     status=EXCLUDED.status,
                     customer_id=COALESCE(orders.customer_id, EXCLUDED.customer_id),
                     subscription_id=COALESCE(orders.subscription_id, EXCLUDED.subscription_id)"""
            cur.execute(q, (session_id, email, plan, api_key, status, datetime.datetime.utcnow().isoformat()+"Z", customer_id, subscription_id))
        else:
            existing = orders_get(session_id)
            if existing:
                cur.execute("UPDATE orders SET email=?,plan=?,api_key=COALESCE(api_key,?),status=?,customer_id=COALESCE(customer_id,?),subscription_id=COALESCE(subscription_id,?) WHERE session_id=?",
                            (email, plan, api_key, status, customer_id, subscription_id, session_id))
            else:
                cur.execute("INSERT INTO orders(session_id,email,plan,api_key,status,created_at,customer_id,subscription_id) VALUES (?,?,?,?,?,?,?,?)",
                            (session_id, email, plan, api_key, status, datetime.datetime.utcnow().isoformat()+"Z", customer_id, subscription_id))
        con.commit()

def orders_get(session_id: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE session_id=%s" if DB_IS_PG else \
            "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE session_id=?"
        cur.execute(q, (session_id,))
        row = cur.fetchone()
        if not row: return None
        return {"session_id": row[0], "email": row[1], "plan": row[2], "api_key": row[3],
                "status": row[4], "created_at": row[5], "customer_id": row[6], "subscription_id": row[7]}

def orders_find_by_customer(customer_id: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE customer_id=%s ORDER BY created_at DESC LIMIT 1" if DB_IS_PG else \
            "SELECT session_id,email,plan,api_key,status,created_at,customer_id,subscription_id FROM orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 1"
        cur.execute(q, (customer_id,))
        row = cur.fetchone()
        if not row: return None
        return {"session_id": row[0], "email": row[1], "plan": row[2], "api_key": row[3],
                "status": row[4], "created_at": row[5], "customer_id": row[6], "subscription_id": row[7]}

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
    return RedirectResponse(url=session.url, status_code=303)

@app.post("/billing/portal", tags=["Billing"])
def billing_portal(session_id: str = Form(...)):
    if not SUBSCRIBE_ENABLED:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    rec = orders_get(session_id)
    if not rec or not rec.get("customer_id"):
        raise HTTPException(status_code=404, detail="Order not found")
    sess = stripe.billing_portal.Session.create(customer=rec["customer_id"], return_url=f"{PUBLIC_BASE_URL}/pricing")
    return RedirectResponse(url=sess.url, status_code=303)

@app.get("/billing/success", response_class=HTMLResponse, tags=["Billing"])
def billing_success(session_id: str = Query(...)):
    rec = orders_get(session_id)
    if rec and rec.get("api_key"):
        plan_label = PLANS.get(rec["plan"], {}).get("label", rec["plan"])
        plan_limit = PLANS.get(rec["plan"], {}).get("monthly_limit", 0)
        content = f"""
<div class="alert alert-success" style="margin-bottom:20px">Payment confirmed. Welcome to {plan_label}!</div>
<div class="key-box">{rec['api_key']}</div>
<p style="font-size:13px;color:var(--muted);margin-top:12px">
  Stored for {rec.get('email') or '(no email)'}. &nbsp;
  {plan_limit:,} requests / month.
</p>
<div style="display:flex;gap:10px;margin-top:20px;flex-wrap:wrap">
  <a class="btn btn-primary" href="/playground?key={rec['api_key']}">Open Playground &rarr;</a>
  <form method='post' action='/billing/portal' style='display:inline'><input type='hidden' name='session_id' value='{session_id}'/><button class='btn btn-outline' type='submit'>Manage billing</button></form>
  <a class="btn btn-outline" href="/pricing">API Docs</a>
</div>"""
    else:
        content = "<p>Thanks! Finalizing your subscription — refresh in a few seconds to see your key.</p>"

    plan_js = rec.get("plan", "") if rec else ""
    body = f"""
<div class="wrap-sm" style="padding:40px 0">
  <div class="card">
    <h1 style="font-size:22px;font-weight:700;margin-bottom:20px">Payment successful</h1>
    {content}
  </div>
</div>
<script>if(window.plausible){{plausible('SubscribeSuccess',{{props:{{plan:'{plan_js}'}}}});}}</script>
"""
    return HTMLResponse(_page("SheetsJSON — Thank you!", body))

@app.post("/stripe/webhook", tags=["Billing"])
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

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
                msg["Subject"] = f"Your SheetsJSON {PLANS[plan]['label']} API Key"
                msg["From"] = SMTP_USER; msg["To"] = email
                msg.set_content(f"Thanks for subscribing to SheetsJSON ({plan}).\n\nYour API key:\n\n{k}\n\nDocs: {PUBLIC_BASE_URL}/pricing\nUsage: {PUBLIC_BASE_URL}/usage\n")
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls(); smtp.login(SMTP_USER, SMTP_PASS); smtp.send_message(msg)
            except Exception:
                pass

    elif t in ("customer.subscription.deleted", "invoice.payment_failed"):
        obj = event["data"]["object"]
        customer_id = obj.get("customer")
        rec = orders_find_by_customer(customer_id) if customer_id else None
        if rec and rec.get("api_key"):
            dp = CANCEL_DOWNGRADE_PLAN
            dl = PLANS.get(dp, PLANS["free"])["monthly_limit"]
            if KEYS_BACKEND == "db":
                keys_db_update(rec["api_key"], plan=dp, monthly_limit=dl)
            else:
                keys = load_keys_file()
                if rec["api_key"] in keys:
                    keys[rec["api_key"]]["plan"] = dp
                    keys[rec["api_key"]]["monthly_limit"] = dl
                    save_keys_file(keys)

    return {"ok": True}


# =============================================================================
# STARTUP
# =============================================================================
@app.on_event("startup")
def _startup():
    db_init()

@app.get("/_debug/routes")
def _debug_routes():
    return [{"path": r.path, "methods": sorted(list(getattr(r, "methods", [])))} for r in app.routes]

if __name__ == "__main__":
    uvicorn_run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
