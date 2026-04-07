# Changelog

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
