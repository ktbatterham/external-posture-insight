# Today Checklist

- [x] P2-1: Normalize panel language so positives stay under `Strengths` and only actionable items appear under `Watch points`
- [x] P2-2: Run a 3-target manual QA pass (`https://ek.co`, `https://bbc.co.uk`, `https://github.com`) and capture outcomes
- [x] P2-3: Update `CHANGELOG.md` with the latest deploy hardening + UX consistency work

## Carry-over

- [ ] Verify Priority Actions ordering always reflects weakest category first
- [ ] Verify trend sparkline behavior with 1, 2, and 7+ snapshots
- [ ] Add empty-state copy for monitoring trend when only one snapshot exists
- [ ] Add small unit tests for priority ranking logic (`src/lib/priorities.ts`)
- [ ] Add unit tests for area score consistency rules (`src/lib/posture.ts`)
- [ ] Decide whether to include category deltas in exported PDF/Markdown summary headline
- [ ] Final UX micro-pass on spacing/typography for Monitoring + Posture Summary
- [ ] Prepare release notes draft for next version bump (what changed + why it matters)
