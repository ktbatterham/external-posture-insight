# Today Checklist

- [x] P2-1: Normalize panel language so positives stay under `Strengths` and only actionable items appear under `Watch points`
- [x] P2-2: Run a 3-target manual QA pass (`https://ek.co`, `https://bbc.co.uk`, `https://github.com`) and capture outcomes
- [x] P2-3: Update `CHANGELOG.md` with the latest deploy hardening + UX consistency work

## Next Session (Later Today)

- [x] Priority Actions sanity pass: ensure weakest category always drives at least one action via fallback rule in `src/lib/priorities.ts`
- [x] Monitoring trend QA: validate 1, 2, and 7+ snapshot behavior in code path (single-snapshot empty-state now renders instead of returning null)
- [x] Add monitoring trend empty-state copy when only one snapshot exists
- [x] Add tests for priority ranking logic (`src/lib/priorities.ts`)
- [x] Add tests for area-score consistency rules (`src/lib/posture.ts`)
- [x] UX micro-pass on Monitoring + Posture Summary spacing/typography
- [x] Decide and implement whether category deltas belong in PDF/Markdown report headlines (decision: keep out of headline; now stated explicitly in exports)
- [x] Draft release notes for the next version bump

## Carry-over

- [x] Verify Priority Actions ordering always reflects weakest category first (enforced via weakest-area fallback action)
- [x] Verify trend sparkline behavior with 1, 2, and 7+ snapshots in component logic (manual browser visual pass still recommended)
- [x] Add empty-state copy for monitoring trend when only one snapshot exists
- [x] Add small unit tests for priority ranking logic (`src/lib/priorities.ts`)
- [x] Add unit tests for area score consistency rules (`src/lib/posture.ts`)
- [x] Decide whether to include category deltas in exported PDF/Markdown summary headline
- [x] Final UX micro-pass on spacing/typography for Monitoring + Posture Summary
- [x] Prepare release notes draft for next version bump (what changed + why it matters)
