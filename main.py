import os, time, io, csv, json, requests, sqlite3, datetime, re, hashlib, smtplib, uuid, secrets
from typing import List, Dict, Optional, Tuple
from email.message import EmailMessage
from urllib.parse import urlparse, parse_qs

from fastapi import FastAPI, HTTPException, Query, Header, Request, Response, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response as FastAPIResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from uvicorn import run as uvicorn_run

# ---------- App ----------
app = FastAPI(
    title="SheetsJSON",
    version="0.7.0",
    openapi_tags=[
        {"name": "API", "description": "Convert Google Sheets CSV → JSON"},
        {"name": "Account", "description": "Usage & limits"},
        {"name": "Admin", "description": "Key management"},
    ],
)
app.add_middleware(GZipMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------- Config ----------
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", "300"))
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
KEYS_PATH = os.getenv("KEYS_PATH", "keys.json")
USAGE_DB = os.getenv("USAGE_DB_PATH", "usage.db")
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
    "free": {"price": 0, "monthly_limit": 200, "label": "Free"},
    "pro":  {"price": 9, "monthly_limit": 5000, "label": "Pro"},
    "plus": {"price": 19, "monthly_limit": 25000, "label": "Plus"},
}

# ---------- In-memory data ----------
_cache: Dict[str, Dict] = {}    # csv_url -> {"ts": float, "rows": List[dict], "raw_sha": str}
_rl: Dict[str, List[float]] = {}  # rate limit buckets: key/ip -> [timestamps]

# ---------- Keys ----------
def load_keys() -> Dict[str, Dict]:
    env = os.getenv("KEYS_JSON")
    if env:
        try:
            return json.loads(env)
        except Exception:
            pass
    if not os.path.exists(KEYS_PATH):
        return {}
    with open(KEYS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_keys(keys: Dict[str, Dict]):
    with open(KEYS_PATH, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)

KEYS = load_keys()

def issue_key(plan: str, limit_override: Optional[int] = None) -> str:
    plan = plan.lower()
    if plan not in PLANS:
        plan = "free"
    while True:
        k = uuid.uuid4().hex.upper()
        if k not in KEYS:
            break
    KEYS[k] = {"plan": plan, "monthly_limit": int(limit_override or PLANS[plan]["monthly_limit"])}
    save_keys(KEYS)
    return k

def get_limit_for_key(api_key: str) -> int:
    meta = KEYS.get(api_key)
    if not meta:
        return -1
    return int(meta.get("monthly_limit", 0))

# ---------- Usage (SQLite) ----------
def init_db():
    con = sqlite3.connect(USAGE_DB)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            api_key TEXT NOT NULL,
            period  TEXT NOT NULL, -- 'YYYY-MM'
            count   INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (api_key, period)
        )
    """)
    con.commit()
    con.close()

def current_period() -> str:
    now = datetime.datetime.utcnow()
    return now.strftime("%Y-%m")

def get_usage(api_key: str, period: Optional[str] = None) -> int:
    period = period or current_period()
    con = sqlite3.connect(USAGE_DB)
    cur = con.cursor()
    cur.execute("SELECT count FROM usage WHERE api_key=? AND period=?", (api_key, period))
    row = cur.fetchone()
    con.close()
    return int(row[0]) if row else 0

def increment_usage(api_key: str, amount: int = 1) -> int:
    period = current_period()
    con = sqlite3.connect(USAGE_DB)
    cur = con.cursor()
    cur.execute("INSERT OR IGNORE INTO usage(api_key, period, count) VALUES(?, ?, 0)", (api_key, period))
    cur.execute("UPDATE usage SET count = count + ? WHERE api_key=? AND period=?", (amount, api_key, period))
    con.commit()
    cur.execute("SELECT count FROM usage WHERE api_key=? AND period=?", (api_key, period))
    row = cur.fetchone()
    con.close()
    return int(row[0]) if row else 0

# ---------- Filtering / sorting ----------
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
        return v/100.0 if pct else v
    except Exception:
        return None

def _match_filter(row_val: Optional[str], op: str, val: str) -> bool:
    if op in (":", "!=", "~", "^", "$"):
        a = (row_val or "").strip().lower(); b = val.strip().lower()
        return {":": a==b, "!=": a!=b, "~": b in a, "^": a.startswith(b), "$": a.endswith(b)}[op]
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
    if not (u.netloc.endswith("docs.google.com")):
        raise HTTPException(status_code=400, detail="Only Google Sheets 'Publish to web → CSV' links are allowed")
    qs = parse_qs(u.query)
    if "output" not in qs or "csv" not in [v.lower() for v in qs["output"]]:
        raise HTTPException(status_code=400, detail="csv_url must include output=csv")
    if "/pub" not in u.path:
        raise HTTPException(status_code=400, detail="csv_url must be a published CSV (path should contain /pub)")

# ---------- CSV fetch (delimiter sniff + size limit + cache) ----------
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

# ---------- API key enforcement ----------
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

# ---------- Rate limit helper ----------
def rate_limit_ok(bucket: str) -> bool:
    now = time.time()
    window = 60.0
    lim = RATE_LIMIT_PER_MIN
    arr = _rl.get(bucket, [])
    # drop old
    arr = [t for t in arr if now - t < window]
    if len(arr) >= lim:
        _rl[bucket] = arr
        return False
    arr.append(now)
    _rl[bucket] = arr
    return True

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
    return f"""
<meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{title}</title><link rel="icon" href="/favicon.svg">
<style>
  :root{{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#6ea8fe;}}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}}
  .wrap{{max-width:960px;margin:40px auto;padding:0 16px}}
  .card{{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}}
  h1{{margin:0 0 6px;font-size:28px}} p{{margin:0 0 16px;color:var(--muted)}}
  header{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
  header img{{width:36px;height:36px}}
  nav a{{color:#9cc2ff;margin-right:14px;text-decoration:none}} nav a:hover{{text-decoration:underline}}
  label{{display:block;margin:12px 0 6px;color:#c8d1f5}}
  input,textarea,button,select{{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}}
  textarea{{min-height:64px}}
  button{{background:var(--accent);border:none;color:#04122d;font-weight:700;cursor:pointer}}
  .grid{{display:grid;gap:12px}} @media(min-width:820px){{.grid{{grid-template-columns:1.5fr 1fr}}}}
  pre{{background:#0a0f24;border:1px solid #26335f;border-radius:12px;padding:14px;overflow:auto}}
  small{{color:#muted}} .row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
  .hint{{font-size:13px;color:#aab8e6}} .pill{{display:inline-block;background:#0a1638;border:1px solid #24336a;border-radius:99px;padding:4px 8px;margin-right:6px;color:#a9b8ee}}
  a{{color:#9cc2ff}} #status{{margin:8px 0 0 0;font-size:13px;color:#aab8e6}} code{{background:#0a0f24;border:1px solid #26335f;border-radius:6px;padding:0 4px}}
  .pricegrid{{display:grid;gap:12px}} @media(min-width:720px){{.pricegrid{{grid-template-columns:repeat(3,1fr)}}}}
  .plan{{background:#0e1630;border:1px solid #233366;border-radius:14px;padding:16px}}
  .plan h3{{margin:0 0 6px}} .cta{{margin-top:8px}}
  table{{width:100%;border-collapse:collapse}} th,td{{padding:8px;border-bottom:1px solid #233366;text-align:left}}
  .btn{{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:#eaf0ff;text-decoration:none}}
</style>"""

# ---------- Public pages (same as before) ----------
# ... (Home, Pricing, Request forms unchanged from v0.6.1 for brevity)
# I’ll inline the same HTML from your 0.6.1 here:

HOME_HTML = f"""<!doctype html><html lang="en"><head>{_html_head("SheetsJSON — CSV → JSON API")}</head>
<body><div class="wrap">
  <header><img src="/logo.svg" alt="SheetsJSON logo"/><div><strong>SheetsJSON</strong><br/><small class="hint">Google Sheets → JSON API</small></div></header>
  <nav><a href="/">Home</a><a href="/pricing">Pricing & Docs</a><a href="/docs">Swagger</a></nav>
  <div class="card"><h1>Try it now</h1><p>Paste a Google Sheets <strong>Publish to web → CSV</strong> link, your API key, and press Fetch.</p>
    <div class="grid"><div>
      <label>Google Sheets CSV URL</label><input id="csv" placeholder="https://docs.google.com/.../pub?output=csv"/>
      <label>API key <small class="hint">(header <code>x-api-key</code> or <code>?key=</code>)</small></label><input id="key" placeholder="FREE_EXAMPLE_KEY_123"/>
      <div class="row"><div><label><span class="pill">optional</span> select</label><input id="select" placeholder="name,email"/></div>
      <div><label><span class="pill">optional</span> order <small class="hint">(e.g., <code>price:num</code>, <code>-age:num</code>, or <code>name</code>)</small></label><input id="order" placeholder="price:num"/></div></div>
      <div class="row"><div><label><span class="pill">optional</span> limit</label><input id="limit" type="number" placeholder="50"/></div>
      <div><label><span class="pill">optional</span> offset</label><input id="offset" type="number" placeholder="0"/></div></div>
      <label><span class="pill">optional</span> filters (one per line)</label>
      <textarea id="filters" placeholder="status:active&#10;name~ali&#10;age&gt;=21&#10;price&lt;100"></textarea>
      <small class="hint">Supported: <code>col:value</code>, <code>col!=v</code>, <code>col~v</code>, <code>col^v</code>, <code>col$v</code>, <code>col&gt;=num</code>/<code>&lt;=</code>/<code>&gt;</code>/<code>&lt;</code>. Add <code>cache_bypass=1</code> in query to refetch.</small>
      <div class="row" style="margin-top:8px"><button id="go" type="button">Fetch JSON</button><button id="usage" type="button">Check Usage</button></div>
      <div id="status">Ready.</div><small class="hint">Need a key? <a href="/request-key">Request one</a>.</small></div>
      <div><label>Result</label><pre id="out">Waiting…</pre><label>Curl</label><pre id="curl"># will appear after a request</pre><label>ETag</label><pre id="etag"># returns entity tag for caching</pre></div>
    </div>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);
function buildURL() {{
  const u = new URL(window.location.origin + "/v1/fetch");
  const filters = $("filters").value.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
  u.searchParams.set("csv_url", $("csv").value.trim());
  const sel = $("select").value.trim(); if (sel) u.searchParams.set("select", sel);
  const ord = $("order").value.trim();  if (ord) u.searchParams.set("order", ord);
  const lim = $("limit").value.trim();  if (lim) u.searchParams.set("limit", lim);
  const off = $("offset").value.trim(); if (off) u.searchParams.set("offset", off);
  filters.forEach(f => u.searchParams.append("filter", f));
  return u;
}}
async function runFetch() {{
  $("status").textContent = "Loading…";
  const key = $("key").value.trim();
  const url = buildURL();
  try {{
    const res = await fetch(url, key ? {{ headers: {{ "x-api-key": key }} }} : undefined);
    $("status").textContent = "HTTP " + res.status;
    const text = await res.text();
    const etag = res.headers.get("etag"); $("etag").textContent = etag ? etag : "(none)";
    try {{ $("out").textContent = JSON.stringify(JSON.parse(text), null, 2); }} catch {{ $("out").textContent = text; }}
    const curl = ['curl', key ? "-H \\"x-api-key: " + key.replace(/"/g,'\\\\\\"') + "\\"" : "", etag ? "-H \\"If-None-Match: " + etag + "\\"" : "", '"' + url.toString().replace(/"/g,'\\"') + '"'].filter(Boolean).join(" ");
    $("curl").textContent = curl;
  }} catch (e) {{ $("status").textContent = "Error"; $("out").textContent = "Error: " + e; console.error(e); }}
}}
async function runUsage() {{
  $("status").textContent = "Loading usage…";
  const key = $("key").value.trim(); if (!key) {{ $("out").textContent = "Add your API key first."; $("status").textContent = "Ready."; return; }}
  try {{
    const res = await fetch("/v1/usage", {{ headers: {{ "x-api-key": key }} }}); $("status").textContent = "HTTP " + res.status;
    const text = await res.text(); try {{ $("out").textContent = JSON.stringify(JSON.parse(text), null, 2); }} catch {{ $("out").textContent = text; }}
  }} catch (e) {{ $("status").textContent = "Error"; $("out").textContent = "Error: " + e; console.error(e); }}
}}
$("go").addEventListener("click", runFetch); $("usage").addEventListener("click", runUsage);
</script></body></html>
"""

def fmt_price(n: int) -> str: return "$0" if n == 0 else f"${n}/mo"

PRICING_HTML = f"""<!doctype html><html lang="en"><head>{_html_head("SheetsJSON — Pricing & Docs")}</head>
<body><div class="wrap">
  <header><img src="/logo.svg" alt="SheetsJSON logo" style="width:36px;height:36px;margin-right:8px"/><strong>SheetsJSON</strong></header>
  <nav><a href="/">Home</a><a href="/pricing">Pricing & Docs</a><a href="/docs">Swagger</a></nav>
  <div class="card"><h1>Pricing</h1>
    <div class="pricegrid">
      <div class="plan"><h3>{PLANS['free']['label']}</h3>
        <p><strong>{fmt_price(PLANS['free']['price'])}</strong></p>
        <ul><li>{PLANS['free']['monthly_limit']} requests / month</li><li>5-minute server cache</li><li>Filters & sorting</li></ul>
        <div class="cta"><a class="hint" href="/request-key">Get a Free key →</a></div>
      </div>
      <div class="plan"><h3>{PLANS['pro']['label']}</h3>
        <p><strong>{fmt_price(PLANS['pro']['price'])}</strong></p>
        <ul><li>{PLANS['pro']['monthly_limit']} requests / month</li><li>Priority cache & support</li><li>ETag / client caching</li></ul>
        <div class="cta"><a class="hint" href="/request-key">Request Pro key →</a></div>
      </div>
      <div class="plan"><h3>{PLANS['plus']['label']}</h3>
        <p><strong>{fmt_price(PLANS['plus']['price'])}</strong></p>
        <ul><li>{PLANS['plus']['monthly_limit']} requests / month</li><li>Higher limits on demand</li><li>Team usage reporting</li></ul>
        <div class="cta"><a class="hint" href="/request-key">Request Plus key →</a></div>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:14px"><h1>Quick Docs</h1>
    <p><strong>Endpoint:</strong> <code>GET /v1/fetch</code></p>
    <p><strong>Header:</strong> <code>x-api-key: YOUR_KEY</code> (or <code>?key=YOUR_KEY</code>)</p>
    <p><strong>Required:</strong> <code>csv_url</code> → Google Sheets <em>Publish to web → CSV</em> link</p>
    <ul>
      <li><code>select</code>: e.g., <code>name,email</code></li>
      <li><code>filter</code> (repeatable): <code>col:value</code>, <code>col!=v</code>, <code>col~v</code>, <code>col^v</code>, <code>col$v</code>, numeric <code>col&gt;=num</code>/<code>&lt;=</code>/<code>&gt;</code>/<code>&lt;</code></li>
      <li><code>order</code>: string <code>col</code> or numeric <code>col:num</code> (desc with <code>-</code>)</li>
      <li><code>limit</code>, <code>offset</code>; <code>cache_bypass=1</code> to refetch</li>
    </ul>
    <p>Interactive docs at <a href="/docs">/docs</a></p>
  </div>
</div></body></html>
"""

REQUEST_KEY_HTML = f"""<!doctype html><html lang="en"><head>{_html_head("SheetsJSON — Request a Key")}</head>
<body><div class="wrap">
  <header><img src="/logo.svg" alt="SheetsJSON logo" style="width:36px;height:36px;margin-right:8px"/><strong>SheetsJSON</strong></header>
  <nav><a href="/">Home</a><a href="/pricing">Pricing & Docs</a><a href="/docs">Swagger</a></nav>
  <div class="card"><h1>Request an API Key</h1>
    <p class="hint">Free keys are issued automatically. Pro/Plus keys are also issued here for demo purposes.</p>
    <form method="post" action="/request-key">
      <label>Name</label><input name="name" required />
      <label>Email</label><input name="email" type="email" required />
      <label>Plan</label>
      <select name="plan">
        <option value="free">Free ({PLANS['free']['monthly_limit']} req/mo)</option>
        <option value="pro">Pro ({PLANS['pro']['monthly_limit']} req/mo) – ${PLANS['pro']['price']}/mo</option>
        <option value="plus">Plus ({PLANS['plus']['monthly_limit']} req/mo) – ${PLANS['plus']['price']}/mo</option>
      </select>
      <label>Use case</label><textarea name="use_case" placeholder="How will you use SheetsJSON?"></textarea>
      <input name="company" style="display:none" autocomplete="off" /> <!-- honeypot -->
      <div style="margin-top:8px"><button type="submit">Submit</button></div>
    </form>
    <p class="hint" style="margin-top:8px">We’ll show your key on the next screen. (For production, wire payments or approval flow.)</p>
  </div>
</div></body></html>
"""

@app.get("/", response_class=HTMLResponse)
def home(): return HTMLResponse(HOME_HTML)

@app.get("/pricing", response_class=HTMLResponse)
def pricing(): return HTMLResponse(PRICING_HTML)

@app.get("/request-key", response_class=HTMLResponse)
def request_key_form(): return HTMLResponse(REQUEST_KEY_HTML)

@app.post("/request-key")
async def request_key_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    plan: str = Form("free"),
    use_case: str = Form(""),
    company: str = Form("")
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
    # store request
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
    # auto-issue key
    key_text = issue_key(payload["plan"]) if KEY_AUTO_ISSUE else None
    key_html = (f"<p>Your <strong>{PLANS[payload['plan']]['label']}</strong> API key:</p>"
                f"<pre style='background:#0a0f24;border:1px solid #26335f;border-radius:8px;padding:12px'>{key_text}</pre>"
                f"<p class='hint'>Limit: {PLANS[payload['plan']]['monthly_limit']} req/mo. "
                f"Use header <code>x-api-key</code> or query <code>?key=</code>.</p>") if key_text else "<p>We’ll email your key shortly.</p>"
    return HTMLResponse(f"<!doctype html><meta charset='utf-8'><title>Thanks</title><body style='font-family:system-ui;padding:2rem;background:#0b1020;color:#eef2ff'><h2>Thanks — your request was received.</h2>{key_html}<p><a style='color:#9cc2ff' href='/'>← Back to Home</a></p></body>", status_code=200)

# ---------- Health ----------
@app.get("/healthz")
def healthz(): return {"ok": True, "version": "0.7.0"}

# ---------- Rate-limited API ----------
def rl_or_429(request: Request, api_key: Optional[str]):
    ident = api_key or (request.client.host if request.client else "unknown")
    if not rate_limit_ok(ident):
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")

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
    if (request.headers.get("if-none-match") or "") == etag:
        return Response(status_code=304)
    body = {"rows": data, "meta": {
        "total_rows": len(rows), "returned": len(data),
        "cached_seconds_left": max(0, CACHE_TTL - int(time.time() - _cache.get(csv_url, {}).get("ts", 0))),
        "cache_ttl_seconds": CACHE_TTL, "api_key": api_key if REQUIRE_API_KEY else None, "etag": etag,
    }}
    return JSONResponse(content=body, headers={"ETag": etag})

@app.get("/v1/usage", tags=["Account"])
def usage(
    request: Request,
    api_key_header: Optional[str] = Header(None, alias="x-api-key", description="Your API key", example="FREE_EXAMPLE_KEY_123"),
    key: Optional[str] = Query(None, description="API key (alt)", example="FREE_EXAMPLE_KEY_123"),
):
    if not REQUIRE_API_KEY:
        return {"message": "API key requirement is disabled."}
    api_key = api_key_header or key
    rl_or_429(request, api_key or (request.client.host if request.client else "unknown"))
    if not api_key or get_limit_for_key(api_key) <= 0:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    plan = (KEYS.get(api_key) or {}).get("plan")
    return {"api_key": api_key, "plan": plan, "period": current_period(),
            "used": get_usage(api_key), "limit": get_limit_for_key(api_key)}

# ---------- Admin (HTTP Basic) ----------
security = HTTPBasic()

def admin_guard(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, ADMIN_USER)
    p_ok = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return True

@app.get("/admin/keys", tags=["Admin"])
def admin_keys_page(auth: bool = Depends(admin_guard)):
    # simple HTML table of keys with forms for actions
    rows = []
    for k, meta in KEYS.items():
        plan = meta.get("plan", "?"); lim = meta.get("monthly_limit", "?")
        rows.append(f"<tr><td><code>{k}</code></td><td>{plan}</td><td>{lim}</td>"
                    f"<td><form method='post' action='/admin/keys/update' style='display:inline'>"
                    f"<input type='hidden' name='api_key' value='{k}'/>"
                    f"<select name='plan'><option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select>"
                    f"<input name='monthly_limit' type='number' placeholder='(keep)' style='width:120px'/>"
                    f"<button class='btn' type='submit'>Update</button></form> "
                    f"<form method='post' action='/admin/keys/revoke' style='display:inline;margin-left:6px'>"
                    f"<input type='hidden' name='api_key' value='{k}'/><button class='btn' type='submit'>Revoke</button></form></td></tr>")
    table = "\n".join(rows) or "<tr><td colspan='4'><em>No keys yet.</em></td></tr>"
    html = f"""<!doctype html><html><head>{_html_head("Admin — Keys")}</head><body>
    <div class='wrap'><div class='card'>
      <h1>Admin — Keys</h1>
      <form method='post' action='/admin/keys/mint' style='margin:8px 0'>
        <strong>Mint:</strong> plan
        <select name='plan'><option value='free'>free</option><option value='pro'>pro</option><option value='plus'>plus</option></select>
        limit <input name='monthly_limit' type='number' placeholder='(default)' style='width:120px'/>
        <button class='btn' type='submit'>Create</button>
      </form>
      <table><thead><tr><th>API key</th><th>Plan</th><th>Monthly limit</th><th>Actions</th></tr></thead><tbody>
        {table}
      </tbody></table>
    </div></div></body></html>"""
    return HTMLResponse(html)

@app.post("/admin/keys/mint", tags=["Admin"])
def admin_mint_key(plan: str = Form("free"), monthly_limit: Optional[int] = Form(None), auth: bool = Depends(admin_guard)):
    k = issue_key(plan, monthly_limit)
    return PlainTextResponse(f"Created key: {k}\n\nGo back: /admin/keys")

@app.post("/admin/keys/update", tags=["Admin"])
def admin_update_key(api_key: str = Form(...), plan: str = Form("free"), monthly_limit: Optional[int] = Form(None), auth: bool = Depends(admin_guard)):
    if api_key not in KEYS:
        raise HTTPException(status_code=404, detail="Key not found")
    KEYS[api_key]["plan"] = plan.lower() if plan.lower() in PLANS else "free"
    if monthly_limit is not None and str(monthly_limit).strip() != "":
        KEYS[api_key]["monthly_limit"] = int(monthly_limit)
    save_keys(KEYS)
    return PlainTextResponse("Updated.\n\nGo back: /admin/keys")

@app.post("/admin/keys/revoke", tags=["Admin"])
def admin_revoke_key(api_key: str = Form(...), auth: bool = Depends(admin_guard)):
    if api_key in KEYS:
        del KEYS[api_key]
        save_keys(KEYS)
    return PlainTextResponse("Revoked (if it existed).\n\nGo back: /admin/keys")

# ---------- Startup ----------
@app.on_event("startup")
def _startup(): init_db()

if __name__ == "__main__":
    uvicorn_run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
