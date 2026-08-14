import assert from "node:assert/strict";
import test from "node:test";

import {
  filterWorkflowReferences,
  workflowUsesPinnedReference,
} from "./fetchPackageSignals.mjs";

const pinned = "uses: this-is-securl/securl/.github/workflows/securl-release-evidence.yml@release-evidence-v1.0.2";

test("recognises only the exact pinned release-evidence reference", () => {
  assert.equal(workflowUsesPinnedReference(`jobs:\n  evidence:\n    ${pinned}\n`), true);
  assert.equal(workflowUsesPinnedReference(`${pinned} # immutable release\n`), true);
  assert.equal(workflowUsesPinnedReference(pinned.replace("v1.0.2", "main")), false);
  assert.equal(workflowUsesPinnedReference(`run: echo ${pinned}`), false);
});

test("counts unique external repositories with references in workflow files", async () => {
  const rows = [
    {
      repository: { fullName: "example/consumer" },
      path: ".github/workflows/release.yml",
      url: "https://github.com/example/consumer/blob/main/.github/workflows/release.yml",
      source: `jobs:\n  evidence:\n    ${pinned}\n`,
    },
    {
      repository: { fullName: "example/consumer" },
      path: ".github/workflows/second.yaml",
      url: "https://github.com/example/consumer/blob/main/.github/workflows/second.yaml",
      source: pinned,
    },
    {
      repository: { fullName: "this-is-securl/securl" },
      path: ".github/workflows/example.yml",
      source: pinned,
    },
    {
      repository: { fullName: "example/docs-only" },
      path: "docs/example.yml",
      source: pinned,
    },
    {
      repository: { fullName: "example/unpinned" },
      path: ".github/workflows/release.yml",
      source: pinned.replace("v1.0.2", "main"),
    },
  ];

  const result = await filterWorkflowReferences(rows, async (row) => row.source);
  assert.equal(result.length, 1);
  assert.equal(result[0].repository.fullName, "example/consumer");
});
