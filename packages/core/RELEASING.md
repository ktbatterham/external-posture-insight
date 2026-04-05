# Releasing `@ktbatterham/external-posture-core`

## Pre-release checklist

1. Update `packages/core/package.json` version.
2. Update `packages/core/CHANGELOG.md`.
3. Run:
   - `npm run build:core`
   - `npm run test:core`
   - `npm run lint`
   - `npm run pack:core`
4. Review the dry-run tarball contents.
5. Confirm `NPM_TOKEN` is present in GitHub repository secrets.

## Release steps

1. Commit the version/changelog update.
2. Tag the release using `core-v<version>`, for example `core-v0.1.0`.
3. Push the tag.
4. Let `.github/workflows/publish-core-package.yml` publish the package.

## Post-release

1. Confirm the package is available on npm.
2. Verify import/install instructions from the published artifact.
3. Move changelog notes from `Unreleased` to the released version section.
