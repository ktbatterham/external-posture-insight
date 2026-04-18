# Changelog

All notable changes to `@ktbatterham/external-posture-core` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning once published.

## [Unreleased]

## [0.6.0] - 2026-04-16

### Added
- CLI policy gating with `--fail-on info|warning|critical` for CI exit-code control.
- CLI regression policy mode with `--fail-on-regression` for baseline/compare workflows.
- Compact `ci-json` CLI output for scan/compare automation pipelines.
- Richer batch scan summaries in summary/Markdown output with aggregate score and strongest/weakest targets.

### Changed
- Updated Vite toolchain compatibility to keep installs stable with current plugin peer dependencies.
- Hardened TLS certificate issuer/subject normalization for stricter TypeScript handling.
- Expanded CLI tests and help-surface assertions for policy mode usage.

## [0.5.0] - 2026-04-16

### Added
- CLI batch scanning via `scan <target...>` with summary, Markdown table, and JSON output support.
- CLI report-to-report comparison via `compare <current-report.json> <baseline-report.json>`.
- CLI SARIF output for both scans and comparisons, including compare mode output focused on newly introduced findings.
- Core CLI test coverage for comparison workflows, JSON/SARIF output, malformed baseline handling, and invalid baseline usage in multi-target scans.

### Changed
- Expanded CLI help and package README examples/documentation to cover batch scans, direct comparisons, and SARIF output.
- Improved CLI argument parsing to support command-oriented workflows while keeping baseline comparisons scoped to single-target scans.

## [0.4.0] - 2026-04-09

### Added
- Passive library risk detection from explicitly versioned script URLs with OSV-backed advisory lookups.
- Score trending in the monitoring UI and a shared history-diff model exported from the core package.
- CLI baseline comparison support via `--baseline <report.json>`.
- Passive DNSSEC posture and certificate-transparency takeover clues from sampled CNAME evidence.

### Changed
- Hardened scan dispatch with stricter public-target revalidation on outbound requests.
- Added explicit timeout handling around OIDC discovery and improved hosted-mode server boundary controls.
- Versioned browser-local monitoring storage and surfaced clearer target-cap feedback in the app.
- Unified app and package diff logic so monitoring and CLI comparisons use the same change model.

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
