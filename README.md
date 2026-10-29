# API Security Gateway

NGINX sits in front of a tiny Flask API and applies a few security rules: rate limiting, request size limits, and allow/deny path patterns. Blocked requests are written as JSON so you can see which rule fired.

```
client  -->  NGINX :8080  -->  API :5000
                 |
                 +-- 429 / 413 / 403
```

## Run

Needs Docker Desktop.

```powershell
docker compose up --build
```

Gateway: `http://127.0.0.1:8080`  
API (localhost only, for the comparison): `http://127.0.0.1:5000`

In another terminal:

```powershell
python scripts/validate.py
```

Stop with `Ctrl+C` in the compose terminal, or `docker compose down`.

## What the gateway does

| Rule | Limit | Response |
| --- | --- | --- |
| Rate limit | 5 req/s per IP, burst 10 | 429 |
| Size limit | body > 1 KB | 413 |
| Allowlist | only `/health` and `/api/` | 403 |
| Denylist | `../`, `<script`, `union select` in the URI | 403 |

Normal traffic is proxied to the API. `/health` is not rate-limited.

## Sample metrics (from `python scripts/validate.py`)

| Check | Status | Result |
| --- | --- | --- |
| normal GET /api/hello | 200 | pass |
| normal GET /health | 200 | pass |
| allowlist GET /secret | 403 | pass |
| denylist union select | 403 | pass |
| denylist path .. | 403 | pass |
| size limit 2KB POST | 413 | pass |
| rate limit burst x30 | ~11 ok / ~19 x429 | pass |

Burst of 30 requests to `/api/hello`:

| Path | Allowed | Blocked | 5xx/err | Error rate |
| --- | --- | --- | --- | --- |
| via gateway :8080 | ~11 | ~19 (429) | 0 | 0% |
| direct API :5000 | ~12 | 0 | ~18 (503) | ~60% |

The gateway absorbs the flood as **429**s. The API never sees most of those requests, so overload **503**s drop.

Rules triggered in that run:

| Rule | Count |
| --- | --- |
| rate_limit | ~19 |
| denylist | 2 |
| allowlist | 1 |
| size_limit | 1 |

Exact counts vary a little with timing. Re-run the script after `docker compose up` to get live numbers.

## Security logs

Each request is appended to `logs/access.json`:

```json
{"time":"2026-09-19T13:05:00+00:00","remote_addr":"192.168.65.1","method":"GET","uri":"/secret","status":403,"security_event":"allowlist","request_length":82,"body_bytes_sent":40}
```

`security_event` is one of: `ok`, `rate_limit`, `size_limit`, `allowlist`, `denylist`.

PowerShell:

```powershell
Get-Content logs\access.json | ConvertFrom-Json | Group-Object security_event | Select-Object Name, Count
```

To start a clean log, stop compose and delete `logs/access.json`.
