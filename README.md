# SheetsJSON

Turn any published Google Sheet into a queryable JSON API — with filters, sorting, pagination, and Stripe subscriptions built in.

## What it does

- `GET /v1/fetch?csv_url=YOUR_SHEET&filter=status:active&order=-price:num` → clean JSON
- API key auth with monthly usage limits (Free / Pro / Plus tiers)
- Stripe subscription checkout + webhook + billing portal
- Embeddable JS widget (`/embed`) for no-code sites
- Full admin panel at `/admin/keys`

## Local setup

```bash
git clone <this-repo>
cd sheetsJSON
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # fill in your values
python main.py
```

Open http://localhost:8000

## Deploy to Render (recommended — free tier available)

1. Push this folder to a GitHub repo
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your repo, set:
   - **Runtime:** Python 3
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add environment variables from `.env.example` (at minimum `ADMIN_PASS` and `PUBLIC_BASE_URL`)
5. For a real DB, add a free Render PostgreSQL instance and set `DATABASE_URL`

## Deploy to Railway

```bash
railway init
railway up
railway variables set ADMIN_PASS=yourpassword PUBLIC_BASE_URL=https://yourapp.up.railway.app
```

Add a PostgreSQL plugin in the Railway dashboard → it auto-sets `DATABASE_URL`.

## Deploy to Fly.io

```bash
fly launch
fly secrets set ADMIN_PASS=yourpassword PUBLIC_BASE_URL=https://yourapp.fly.dev
fly deploy
```

## Stripe setup

1. Create two recurring products in Stripe: **Pro ($9/mo)** and **Plus ($19/mo)**
2. Copy the `price_xxx` IDs → `STRIPE_PRICE_PRO` / `STRIPE_PRICE_PLUS`
3. Add a webhook endpoint pointing to `https://yourdomain.com/stripe/webhook`
4. Enable events: `checkout.session.completed`, `customer.subscription.deleted`, `invoice.payment_failed`
5. Copy the webhook signing secret → `STRIPE_WEBHOOK_SECRET`

## API reference

| Param | Type | Description |
|-------|------|-------------|
| `csv_url` | string | Google Sheets Publish-to-web CSV URL (required) |
| `filter` | string (repeatable) | `col:v` `col!=v` `col~v` `col^v` `col$v` `col>=n` |
| `order` | string | `col` or `col:num`, prefix `-` for descending |
| `select` | string | Comma-separated columns to return |
| `limit` | int | Max rows (1–10000) |
| `offset` | int | Rows to skip |
| `cache_bypass` | 0\|1 | Force re-fetch from Google |

Auth: `x-api-key: YOUR_KEY` header or `?key=YOUR_KEY` query param.

## Pages

| Route | Description |
|-------|-------------|
| `/` | Marketing landing page |
| `/playground` | Interactive API tester |
| `/examples` | Live demo datasets |
| `/pricing` | Pricing + API docs |
| `/request-key` | Self-serve key signup |
| `/usage` | Check monthly usage |
| `/embed` | Embed snippet generator |
| `/admin/keys` | Admin panel (HTTP Basic auth) |
| `/docs` | Auto-generated Swagger UI |

## Environment variables

See `.env.example` for the full list with descriptions.

Minimum required for production:
- `PUBLIC_BASE_URL`
- `ADMIN_PASS`
- `STRIPE_SECRET_KEY`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_PLUS`, `STRIPE_WEBHOOK_SECRET` (for paid plans)
- `DATABASE_URL` (for PostgreSQL; SQLite used otherwise)
