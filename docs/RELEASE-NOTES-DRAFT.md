# Release Notes Draft (Next Version)

## Highlights

- Improved report clarity by making neutral-positive states read as strengths and reserving watch language for actionable items.
- Tightened monitoring UX with clearer trend behavior when only one saved snapshot exists.
- Expanded app-level test coverage with unit tests for posture scoring and priority-action ranking logic.
- Completed dependency maintenance and PR backlog cleanup for current `main`.

## What Changed

### UX and report clarity

- Standardized panel copy from `Review points` to `Watch points` where applicable.
- Updated Monitoring and Posture Summary spacing/typography for better readability and consistency.
- Added explicit single-snapshot trend empty state messaging.

### Priority and scoring behavior

- Ensured weakest posture category is always represented in Priority Actions via a fallback rule.
- Added unit tests for:
  - category scoring thresholds and clamping
  - priority action ordering and fallback behavior

### Export behavior

- Added an explicit export headline change summary for Markdown/HTML exports.
- Documented decision: per-category deltas are intentionally not included in the export headline because per-category historical baselines are not embedded in exports.

## Validation

- `npm run build`
- `npm run test:core`
- `npm run test:app:unit`
- `npm run test:server`

## Follow-ups

- If we want category deltas in export headlines later, we should extend exported artifacts to include previous snapshot area scores.
- Tailwind CSS v4 migration remains intentionally deferred as a dedicated planned migration.
