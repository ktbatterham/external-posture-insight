# @ktbatterham/external-posture-core

[![npm version](https://img.shields.io/npm/v/%40ktbatterham%2Fexternal-posture-core)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

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

This package is published and consumable from npm:

- [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

It is also used by the External Posture Insight app from the local workspace during development.

## Release workflow

- local package check: `npm run pack:core`
- CI verification: `.github/workflows/core-package-checks.yml`
- publish workflow: `.github/workflows/publish-core-package.yml`
- publish requires an `NPM_TOKEN` repository secret

Recommended release flow:

1. update the version in `packages/core/package.json`
2. run `npm run test:core`
3. run `npm run pack:core`
4. create and push a tag like `core-v0.1.1`
5. let the publish workflow release the package

See also:

- `packages/core/CHANGELOG.md`
- `packages/core/RELEASING.md`

## Public API

## CLI

The package now includes a pipe-friendly CLI:

```bash
npx @ktbatterham/external-posture-core scan example.com
```

Scan multiple targets in one run:

```bash
npx @ktbatterham/external-posture-core scan example.com github.com bbc.co.uk
```

Available output formats:

```bash
npx @ktbatterham/external-posture-core scan example.com --format summary
npx @ktbatterham/external-posture-core scan example.com --format json
npx @ktbatterham/external-posture-core scan example.com --format markdown
npx @ktbatterham/external-posture-core scan example.com --format sarif
```

CI policy modes:

```bash
npx @ktbatterham/external-posture-core scan example.com github.com --fail-on warning
npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json --fail-on-regression
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json --fail-on critical --fail-on-regression
```

- `--fail-on` sets exit code `1` when findings at or above the selected severity are present.
- `--fail-on-regression` sets exit code `1` when the baseline comparison detects a regression (score drop, new issues, or worse HTTP status class).

Write results to a file:

```bash
npx @ktbatterham/external-posture-core scan example.com --format json --output report.json
```

Compare against a previously saved JSON report:

```bash
npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json
```

Compare two saved reports directly:

```bash
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json --format sarif
```

Batch scans return:

- summary: one line per target
- markdown: a compact comparison table
- sarif: one SARIF log containing findings across all scanned targets
- json:

```json
{
  "analyses": [{ "...": "scan result" }]
}
```

Direct report comparison returns:

- summary: score, status, and change summary
- markdown: a compact comparison report
- sarif: only findings that are newly introduced in the current report versus the baseline
- json:

```json
{
  "current": { "...": "latest saved report" },
  "baseline": { "...": "older saved report" },
  "diff": { "...": "structured change summary" }
}
```

Show usage:

```bash
npx @ktbatterham/external-posture-core --help
```

### `analyzeUrl(url)`

Run a full posture analysis for a public target.

```js
import { analyzeUrl } from "@ktbatterham/external-posture-core";

const result = await analyzeUrl("https://example.com");
console.log(result.score, result.grade);
```

`analyzeTarget` remains available as a compatibility alias, but `analyzeUrl` is the primary public entrypoint.

When a baseline report is supplied to the CLI, summary and Markdown output append a `Changes Since Baseline` section. JSON output returns:

```json
{
  "analysis": { "...": "latest scan result" },
  "diff": { "...": "structured change summary" }
}
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
