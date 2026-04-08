# Changelog

All notable changes to `@ktbatterham/external-posture-core` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning once published.

## [Unreleased]

## [0.3.0] - 2026-04-08

### Added
- A first-class CLI entrypoint with `scan`, summary/JSON/Markdown output, and file output support.
- Richer monitoring diffs covering certificate windows, third-party providers, AI vendors, identity-provider changes, WAF changes, and CT priority-host changes.
- WAF and edge fingerprinting with passive provider inference.
- Certificate Transparency coverage rollups with prioritized and sampled hosts.

### Changed
- Deepened passive identity discovery with stronger OAuth/OIDC heuristics and less eager same-origin redirect attribution.
- Improved passive-signal messaging and UI consistency for identity, CT, third-party trust, and disclosure/domain trust panels.
- Consolidated duplicated core helpers and documented scanner limits in shared config.

## [0.2.0] - 2026-04-07

### Added
- Passive Identity Provider and OAuth discovery, including public OpenID configuration checks.
- Certificate Transparency discovery with bounded, best-effort lookup behavior.
- Staged strict TypeScript verification for extracted core modules.
- Dependabot configuration and npm publish provenance support for release hygiene.

### Changed
- Replaced regex-driven HTML parsing with a Cheerio-based DOM inspection path.
- Extracted CT, identity, HTML insight, and surface-enrichment logic out of the core scanner monolith.
- Hardened the local server boundary with request validation, basic rate limiting, and safer API error responses.
- Added package `engines` metadata and simplified the repo to a single npm lockfile story.

## [0.1.0] - 2026-04-05

### Added
- Initial extracted scanner core package.
- Passive HTML/client exposure analysis.
- AI surface, third-party trust, DNS/mail posture, exposure, and API-surface analysis.
- OWASP/MITRE-aligned finding labeling.
- Regression fixtures for known false positives.
