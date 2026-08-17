import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyResolvedTransport,
  isMaterialOriginChange,
} from "../dist/link-inspection.js";

test("same-host HTTP to HTTPS is a positive upgrade, not an origin change", () => {
  const initial = new URL("http://example.com/path");
  const destination = new URL("https://example.com/path");

  assert.equal(isMaterialOriginChange(initial, destination), false);
  assert.deepEqual(classifyResolvedTransport(initial, destination), [{
    id: "https_upgrade",
    level: "info",
    title: "Secures with HTTPS",
    detail: "example.com upgrades the connection to HTTPS before the final response.",
  }]);
});

test("HTTP that does not upgrade remains attention-worthy", () => {
  const signals = classifyResolvedTransport(
    new URL("http://example.com/"),
    new URL("http://example.com/final"),
  );
  assert.equal(signals[0].id, "unencrypted_http");
  assert.equal(signals[0].level, "attention");
});

test("cross-host redirects remain material origin changes", () => {
  assert.equal(
    isMaterialOriginChange(
      new URL("http://example.com/"),
      new URL("https://example.net/"),
    ),
    true,
  );
});
