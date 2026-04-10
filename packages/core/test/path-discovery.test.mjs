import assert from "node:assert/strict";
import test from "node:test";
import { normalizeDiscoveredPath, rankDiscoveredPaths } from "../dist/path-discovery.js";

test("normalizeDiscoveredPath keeps same-origin page paths and drops assets", () => {
  const base = new URL("https://example.com/");
  assert.equal(normalizeDiscoveredPath("/login", base), "/login");
  assert.equal(normalizeDiscoveredPath("/assets/app.js", base), null);
  assert.equal(normalizeDiscoveredPath("mailto:test@example.com", base), null);
  assert.equal(normalizeDiscoveredPath("https://other.example.com/login", base), null);
});

test("rankDiscoveredPaths prioritizes sensitive-looking paths", () => {
  const ranked = rankDiscoveredPaths([
    "/contact",
    "/admin",
    "/dashboard",
    "/login",
  ]);

  assert.equal(ranked[0], "/login");
  assert.ok(ranked.indexOf("/admin") < ranked.indexOf("/contact"));
  assert.ok(ranked.indexOf("/dashboard") < ranked.indexOf("/contact"));
});
