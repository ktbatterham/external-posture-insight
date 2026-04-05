import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { analyzeHtmlDocument } from "../src/index.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, "fixtures");

const readFixture = (name) => fs.readFileSync(path.join(fixturesDir, name), "utf8");

test("ignores api-like asset paths in client exposure detection", () => {
  const htmlSecurity = analyzeHtmlDocument("https://apple.com/", readFixture("apple-api-asset.html"));
  assert.equal(htmlSecurity.clientExposureSignals.length, 0);
});

test("does not treat max-image-preview robots metadata as an environment leak", () => {
  const htmlSecurity = analyzeHtmlDocument("https://www.bbc.co.uk/", readFixture("max-image-preview.html"));
  assert.equal(
    htmlSecurity.clientExposureSignals.some((signal) => signal.category === "environment"),
    false,
  );
});

test("does not treat generic crisp css class names as AI/support automation", () => {
  const htmlSecurity = analyzeHtmlDocument("https://sentrustsouthend.co.uk/", readFixture("crisp-wordpress-class.html"));
  assert.equal(htmlSecurity.aiSurface.detected, false);
  assert.equal(htmlSecurity.aiSurface.vendors.length, 0);
});

test("preserves positive client exposure and auth signals when they are explicit", () => {
  const htmlSecurity = analyzeHtmlDocument("https://example.com/", readFixture("client-config-positive.html"));
  assert.equal(
    htmlSecurity.clientExposureSignals.some((signal) => signal.category === "config"),
    true,
  );
  assert.equal(
    htmlSecurity.clientExposureSignals.some(
      (signal) => signal.category === "config" && signal.evidence.includes("environment"),
    ),
    true,
  );
  assert.equal(htmlSecurity.forms.some((form) => form.hasPasswordField), true);
  assert.equal(htmlSecurity.firstPartyPaths.includes("/login"), true);
});
