# External Posture Insight

[![npm version](https://img.shields.io/npm/v/%40ktbatterham%2Fexternal-posture-core)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

External Posture Insight is a low-noise external posture analysis app for public web targets. It inspects a target URL through a local Node API, follows redirects, reads response headers, evaluates TLS certificate details, parses `Set-Cookie` flags, and produces a layered report in the browser.

## Published package

The reusable scanner core is now published on npm:

- [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

This app consumes that core package locally from the workspace during development.

## Release status

- Latest published core package: `@ktbatterham/external-posture-core@0.6.1`
- Latest npm tag: `latest`
- Clean-install smoke test completed from a fresh npm project

## Features

- Live header analysis for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP
- Redirect chain inspection
- TLS certificate trust, issuer, expiry, protocol, cipher, and fingerprint reporting
- Cookie flag analysis for `Secure`, `HttpOnly`, and `SameSite`
- Conservative stack detection from origin, edge, and frontend signals
- Multi-page crawl summaries for important same-origin routes
- Platform-specific remediation snippets for `nginx`, `Apache`, `Cloudflare`, `Vercel`, and `Netlify`
- Local history snapshots with score and header diffs
- `security.txt` discovery and validation
- Domain and email posture checks for MX, SPF, DMARC, CAA, and MTA-STS
- Passive HTML inspection for forms, third-party assets, inline scripts/styles, and missing SRI
- Client config and API exposure signals from passive page analysis
- Auth surface and public data-collection surface summaries
- AI surface and third-party trust analysis
- OWASP/MITRE-aligned finding labels
- Low-noise exposure checks for a tiny set of high-signal paths
- CLI batch scanning and saved-report comparison workflows
- CI policy gating via CLI (`--fail-on` and `--fail-on-regression`)
- SARIF export for CI and security tooling ingestion
- JSON, Markdown, and HTML report export
- Recent scan history in the browser

## Stack

- React + Vite + TypeScript
- Tailwind + shadcn/ui
- Node.js API server using core `http`, `https`, and `tls`
- Reusable core package in `packages/core`

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

## Public deployment guardrails

- In production, startup is blocked unless either `API_KEY` is set or `ALLOW_UNAUTHENTICATED=true` is explicitly set.
- `TRUST_PROXY=true` only applies forwarded-IP attribution when the direct peer is private/local.
- `DEPLOYMENT_MODE=multi-instance` blocks startup by default when only in-memory rate limiting is available.

See:

- [`docs/PUBLIC-DEPLOY-CHECKLIST.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/PUBLIC-DEPLOY-CHECKLIST.md)
- [`docs/OWASP-MITRE-SELF-REVIEW.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/OWASP-MITRE-SELF-REVIEW.md)

## Notes

- Scans are based on what the origin returns for the requested URL at scan time.
- Technology detection is heuristic and intentionally conservative.
- Some sites may block automated requests or respond differently to bots versus browsers.
- The published package is intended for passive or near-passive posture assessment, not exploit testing.
