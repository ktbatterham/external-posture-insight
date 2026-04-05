# @ktbatterham/external-posture-core

Low-noise external posture analysis for public web targets.

This package is the reusable scanner engine extracted from the External Posture Insight app. It is designed for passive or near-passive posture assessment rather than active exploitation or noisy recon.

## What it covers

- HTTP security headers and redirect posture
- TLS and certificate inspection
- Cookie hygiene
- Passive HTML inspection
- AI surface and third-party trust signals
- Low-noise exposure, CORS, API-surface, and DNS/mail posture checks
- OWASP/MITRE-aligned finding labels

## Current status

This package is not published yet. The API is stabilizing and is currently used internally by the app.

## Release workflow

- local package check: `npm run pack:core`
- CI verification: `.github/workflows/core-package-checks.yml`
- publish workflow: `.github/workflows/publish-core-package.yml`
- publish requires an `NPM_TOKEN` repository secret

Recommended release flow:

1. update the version in `packages/core/package.json`
2. run `npm run test:core`
3. run `npm run pack:core`
4. create and push a tag like `core-v0.1.0`
5. let the publish workflow release the package

See also:

- `packages/core/CHANGELOG.md`
- `packages/core/RELEASING.md`

## Public API

### `analyzeTarget(url)`

Run a full posture analysis for a public target.

```js
import { analyzeTarget } from "@ktbatterham/external-posture-core";

const result = await analyzeTarget("https://example.com");
console.log(result.score, result.grade);
```

### `analyzeHtmlDocument(url, html)`

Run passive HTML/content analysis against a fetched HTML document.

```js
import { analyzeHtmlDocument } from "@ktbatterham/external-posture-core";

const htmlSecurity = analyzeHtmlDocument("https://example.com", "<html>...</html>");
console.log(htmlSecurity.clientExposureSignals);
```

## Notes

- Only use this against targets you are authorized to assess.
- The package is intentionally conservative about active probing.
- Scoring is heuristic and should be treated as a prioritization aid, not an absolute security truth.
