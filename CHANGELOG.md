# Changelog

## 2026-04-09

### Added

- Added passive library version risk analysis backed by OSV for explicitly versioned client-side assets
- Added score trending in monitoring history plus shared diff helpers now exposed by the core package
- Added CLI baseline comparison mode for report-vs-report change summaries
- Added DNSSEC posture and passive takeover clues from CT/CNAME observations

### Changed

- Hardened outbound scan requests with stricter public-IP revalidation and tighter OIDC discovery timeout handling
- Added hosted-mode API key support, rate-limit bucket cleanup, and versioned browser-local monitoring storage
- Unified app and package diff generation so browser monitoring and CLI comparisons now share the same model

### Verified

- `npm run release:core:check`
- CLI smoke tests including `--baseline`
- Local build, core tests, lint, and server syntax checks

## 2026-04-08

### Added

- Added a real CLI for the published core package with summary, JSON, and Markdown output modes
- Added richer monitoring diff reporting across transport, providers, AI, identity, WAF, and CT host changes
- Added passive WAF and edge fingerprinting plus richer CT coverage rollups

### Changed

- Deepened passive IdP/OAuth posture analysis while reducing weak same-origin false positives
- Tightened passive signal panel messaging so neutral states no longer read as contradictory
- Polished domain, public trust, disclosure, and third-party trust panel rendering for more consistent report visuals
- Consolidated duplicated core helpers and documented scanner configuration limits

### Verified

- `npm run release:core:check`
- Local CLI smoke tests for summary, JSON, and Markdown output
- Browser sanity checks across the revised trust/identity/third-party panels

## 2026-04-07

### Added

- Added passive Identity Provider / OAuth discovery and Certificate Transparency enrichment to the product surface
- Added Dependabot config and npm provenance publishing support

### Changed

- Extracted more of the scanner core into dedicated modules for CT, identity, HTML insights, and surface enrichment
- Hardened the local analysis API with target validation, simple rate limiting, safer error handling, and static-response security headers
- Clarified in the UI that monitoring remains browser-local and does not continue after the tab is closed
- Removed the stray `bun.lockb` so the repo now follows a single npm lockfile path

### Verified

- `npm run release:core:check`
- Edge-case API checks against live local server instances, including private-target rejection and weird-site scans

## 2026-04-05

### Added

- Published the reusable scanner core as [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
- Added package release workflows, changelog, and release checklist
- Migrated the core package to compiled TypeScript

### Changed

- Updated the repo README to reflect the broader External Posture Insight product
- Added npm badges and package links to the repo and package documentation
- Updated GitHub Actions workflow dependencies to current major versions

### Verified

- `npm run release:core:check`
- Clean consumer install from a fresh npm project
