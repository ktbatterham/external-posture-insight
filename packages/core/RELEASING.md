# Releasing `securl`

## Pre-release checklist

Only release `securl` when the package itself changes. Backend-only API resources, hosted app deploy scripts, Railway settings, Hostinger static deploys, and app-only UI changes do not warrant a core package bump unless they also change files that are published from `packages/core`.

Version bump guidance:

- **Patch**: bug fixes, scoring calibration fixes, false-positive/false-negative corrections, dependency/runtime fixes, or docs/signalling updates intentionally worth republishing.
- **Minor**: new exported helpers, new analysis signals, new CLI options, new report formats, new typed result fields, or additive public API changes.
- **Major**: breaking changes to exported functions, CLI commands/options, package exports, result types, scoring semantics that consumers must handle differently, or supported Node/runtime expectations.

Before deciding to bump, check what changed since the latest core tag:

```sh
git diff --name-status securl-v$(node -p "require('./packages/core/package.json').version")..HEAD -- packages/core package.json package-lock.json
```

1. Update `packages/core/package.json` version.
2. Update `packages/core/CHANGELOG.md`.
3. Run:
   - `npm run release:core:check`
4. Review the dry-run tarball contents.
5. Confirm npm Trusted Publishing is configured for this package:
   - provider: GitHub Actions
   - organization: `this-is-securl`
   - repository: `securl`
   - workflow filename: `publish-core-package.yml`
   - allowed action: `npm publish`

## Release steps

1. Commit the version/changelog update.
2. Tag the exact reviewed merge commit using `securl-v<version>`, for example
   `securl-v1.4.1`.
3. Push the tag.
4. Let `.github/workflows/publish-core-package.yml` publish the package through short-lived npm OIDC credentials.

The publish workflow derives the exact release tag from `packages/core/package.json`,
requires that tag to peel to the checked-out publish commit, verifies the commit is on
`origin/main`, and runs the complete package release gate before publishing. If a manual
workflow dispatch is needed after a tag publish failure, dispatch it against the exact
commit already named by that release tag. Never move or recreate a published tag to make
recovery pass.

## Post-release

1. Confirm npm exposes the version as `latest` with provenance.
2. Install `securl@<version>` in a clean temporary directory and smoke the import and CLI.
3. Confirm the matching GitHub release exists and its tag peels to the published commit.
4. Run `npm run package:signals` and verify repository, registry, tag, and release state
   remain aligned.
