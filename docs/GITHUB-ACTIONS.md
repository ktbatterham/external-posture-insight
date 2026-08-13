# SecURL Release Evidence for GitHub Actions

Use SecURL to attach passive external posture evidence to a deployment or release. The
starter workflow is deliberately non-blocking: it scans one public target, writes the
score and finding counts into the GitHub Actions job summary, and uploads a digest-verifiable
Posture Manifest as a build artifact.

The summary includes one target-prefilled link to the hosted scanner. Opening it, starting
the hosted scan, and saving a watch all remain explicit user actions. The link carries the
`github_actions` source and `release_evidence` campaign so the path can be measured without
collecting repository, workflow, or actor identity.

## Add the reusable workflow

Create `.github/workflows/securl-release-evidence.yml` in the repository that owns the
public target:

```yaml
name: External posture evidence

on:
  workflow_dispatch:
  release:
    types: [published]

permissions:
  contents: read

jobs:
  securl:
    uses: this-is-securl/securl/.github/workflows/securl-release-evidence.yml@release-evidence-v1.0.2
    with:
      target: https://example.com
      scan-mode: quiet
```

Replace `https://example.com` with a public URL you own or are authorized to assess. No
secret or SecURL account is required. The workflow uses the exact reviewed workflow tag,
the published `securl` package with npm provenance, and third-party actions pinned to full
commit SHAs.

## Add a score gate later

First establish that the evidence is stable and useful to the release owner. When the team
has agreed on a real threshold, add it explicitly:

```yaml
    with:
      target: https://example.com
      scan-mode: quiet
      fail-if-score-below: "75"
```

The evidence artifact is still uploaded when the threshold fails, so the failed decision
has a reviewable record. Avoid selecting a threshold only to make the check green.

## What the workflow records

- public target, resolved URL, HTTP status, score, and grade;
- counts of critical, warning, and informational findings;
- scan mode, timing, assessment limitations, and engine version;
- observation ledger, evidence quality, signal clarity, and baseline policy result;
- SHA-256 digest over the canonical Posture Manifest.

It does not send repository names, commit SHAs, GitHub actors, secrets, or local scan
payloads to the hosted SecURL service. The local CLI fetches the public target directly.
Only a person choosing the hosted continuation starts a separate hosted scan.

## Run it without the reusable workflow

```sh
npx securl scan example.com \
  --quiet \
  --format evidence \
  --output securl-release-evidence.json \
  --github-summary "$GITHUB_STEP_SUMMARY"
```

For stricter release decisions, SecURL also supports baseline regression checks, severity
gates, SARIF, JSON, and certificate policy profiles. Start with visible evidence, then add
only the gate your team is prepared to own.
