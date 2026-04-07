# Changelog

All notable changes to `@ktbatterham/external-posture-core` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning once published.

## [Unreleased]

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
