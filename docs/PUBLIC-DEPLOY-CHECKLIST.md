# Public Deploy Checklist

Run this checklist before exposing the server publicly.

## 1) Environment and runtime

- Set `NODE_ENV=production`.
- Set `API_KEY` unless you intentionally allow unauthenticated access.
- If unauthenticated access is intentional, set `ALLOW_UNAUTHENTICATED=true` explicitly.
- Set `TRUST_PROXY=true` only when behind a trusted reverse proxy/load balancer.
- Set `DEPLOYMENT_MODE`:
  - `single-instance` for one server process (default).
  - `multi-instance` for scaled deployments.
- Optional rate-limit tuning:
  - `RATE_LIMIT_MAX_REQUESTS` (default `30`)
  - `RATE_LIMIT_WINDOW_MS` (default `900000`, 15 minutes)

### Multi-instance safety gate

In `multi-instance`, startup is blocked by default when using in-memory rate limiting.

- Temporary override (not recommended for public sustained traffic):
  - `ALLOW_INMEMORY_RATE_LIMITER_IN_MULTI_INSTANCE=true`

This override should only be used during transition to a distributed limiter.

## 2) Pre-release verification

- `npm run -s build`
- `npm run -s test:core`
- `npm run -s test:server`
- `npm run -s lint`
- Confirm no open High/Critical code-scanning alerts on `main`.

## 3) API and abuse protections

- Confirm `/api/analyze` requires API key when `API_KEY` is set.
- Confirm rate limiting behavior from expected client origin path (through proxy in production).
- Confirm proxy IP attribution works as expected in your topology.

## 4) Security headers and static serving

- Confirm static responses include:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
- Confirm encoded traversal attempts are rejected.

## 5) Smoke tests after deploy

- `GET /api/health` returns `ok: true`.
- Health payload includes deployment mode and rate-limit metadata.
- Run one known-safe scan and verify sanitized error responses for invalid targets.
