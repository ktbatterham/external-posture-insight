import assert from "node:assert/strict";
import test from "node:test";

test("package surface exports expected public functions", async () => {
  const pkg = await import("../dist/index.js");

  assert.equal(typeof pkg.analyzeTarget, "function");
  assert.equal(typeof pkg.analyzeUrl, "function");
  assert.equal(typeof pkg.analyzeHtmlDocument, "function");
  assert.equal(typeof pkg.formatErrorMessage, "function");
});
