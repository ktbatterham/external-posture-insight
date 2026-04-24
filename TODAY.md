# Next Session Todo

## 1) Final Human UX Sign-off

- [ ] Run [UX-RELEASE-CANDIDATE-CHECKLIST.md](/Users/keith/Documents/Playground/secure-header-insight/docs/UX-RELEASE-CANDIDATE-CHECKLIST.md) in-browser end-to-end.
- [ ] Confirm top-block alignment on `ek.co`, `bbc.co.uk`, `github.com`, and `wsj.com`.
- [ ] Confirm responsive visual quality at `1280px`, `1024px`, `768px`, and `390px`.
- [ ] Capture any visual defects as a short punch list (max 5 items).

## 2) RC Polish (Only If Needed)

- [ ] Fix any visual punch-list defects from sign-off.
- [ ] Re-run quick smoke checks after fixes:
- [ ] `npm run build`
- [ ] `npm run test:app:unit`

## 3) Release Prep

- [ ] Finalize [RELEASE-NOTES-DRAFT.md](/Users/keith/Documents/Playground/secure-header-insight/docs/RELEASE-NOTES-DRAFT.md) into release-ready notes.
- [ ] Confirm version bump target and scope (`app` narrative + `core` package status).
- [ ] Update `CHANGELOG.md` with final release wording/date.

## 4) Ship Flow

- [ ] Commit any final RC polish.
- [ ] Open PR and merge when green.
- [ ] Tag/release (if we decide to cut immediately).
