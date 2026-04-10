import assert from "node:assert/strict";
import test from "node:test";
import { parseSecurityTxt } from "../dist/security-txt.js";

test("parseSecurityTxt extracts expected RFC 9116 fields", () => {
  const parsed = parseSecurityTxt(
    [
      "Contact: mailto:security@example.com",
      "Expires: 2027-12-31T23:59:59Z",
      "Canonical: https://example.com/.well-known/security.txt",
      "Policy: https://example.com/security",
    ].join("\n"),
    new URL("https://example.com/.well-known/security.txt"),
  );

  assert.equal(parsed.status, "present");
  assert.deepEqual(parsed.contact, ["mailto:security@example.com"]);
  assert.equal(parsed.expires, "2027-12-31T23:59:59Z");
  assert.deepEqual(parsed.policy, ["https://example.com/security"]);
  assert.equal(parsed.issues.length, 0);
});

test("parseSecurityTxt marks missing contact as invalid", () => {
  const parsed = parseSecurityTxt(
    "Expires: 2027-12-31T23:59:59Z",
    new URL("https://example.com/.well-known/security.txt"),
  );

  assert.equal(parsed.status, "invalid");
  assert.equal(parsed.issues.includes("No Contact field found."), true);
});
