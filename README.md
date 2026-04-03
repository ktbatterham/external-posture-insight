# Secure Header Insight

Secure Header Insight is a live website security scanner for HTTP hardening checks. It inspects a target URL through a local Node API, follows redirects, reads response headers, evaluates TLS certificate details, parses `Set-Cookie` flags, and produces a graded report in the browser.

## Features

- Live header analysis for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP
- Redirect chain inspection
- TLS certificate trust, issuer, expiry, protocol, cipher, and fingerprint reporting
- Cookie flag analysis for `Secure`, `HttpOnly`, and `SameSite`
- Heuristic stack detection from server and CDN headers
- Multi-page crawl summaries for important same-origin routes
- Platform-specific remediation snippets for `nginx`, `Apache`, `Cloudflare`, `Vercel`, and `Netlify`
- Local history snapshots with score and header diffs
- `security.txt` discovery and validation
- Domain and email posture checks for MX, SPF, DMARC, CAA, and MTA-STS
- Passive HTML inspection for forms, third-party assets, inline scripts/styles, and missing SRI
- Low-noise exposure checks for a tiny set of high-signal paths
- JSON export for each scan
- Recent scan history in the browser

## Stack

- React + Vite + TypeScript
- Tailwind + shadcn/ui
- Node.js API server using core `http`, `https`, and `tls`

## Local development

```sh
npm install
npm run dev
```

That starts:

- the Vite frontend on `http://localhost:8080`
- the scan API on `http://127.0.0.1:8787`

The frontend proxies `/api/*` requests to the local API in development.

## Production-style run

```sh
npm run build
npm start
```

`npm start` serves the API and the built frontend from the same Node process.

## Notes

- Scans are based on what the origin returns for the requested URL at scan time.
- Technology detection is heuristic and intentionally conservative.
- Some sites may block automated requests or respond differently to bots versus browsers.
