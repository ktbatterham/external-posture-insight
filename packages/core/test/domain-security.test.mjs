import assert from "node:assert/strict";
import test from "node:test";
import { evaluateDmarcPolicy, evaluateSpfPolicy } from "../dist/domain-security.js";

test("evaluateSpfPolicy classifies hardfail, softfail, and permissive SPF records", () => {
  assert.deepEqual(evaluateSpfPolicy(null), {
    status: "missing",
    allMechanism: null,
    dnsLookupMechanisms: 0,
    summary: "No SPF record was detected at the zone apex.",
  });

  const hardfail = evaluateSpfPolicy("v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all");
  assert.equal(hardfail.status, "strong");
  assert.equal(hardfail.allMechanism, "-all");
  assert.equal(hardfail.dnsLookupMechanisms, 1);

  const softfail = evaluateSpfPolicy("v=spf1 include:_spf.example.com ~all");
  assert.equal(softfail.status, "watch");
  assert.equal(softfail.allMechanism, "~all");

  const permissive = evaluateSpfPolicy("v=spf1 +all");
  assert.equal(permissive.status, "weak");
  assert.equal(permissive.allMechanism, "+all");
});

test("evaluateDmarcPolicy classifies enforcing, partial rollout, and monitor-only records", () => {
  assert.deepEqual(evaluateDmarcPolicy(null), {
    status: "missing",
    policy: null,
    subdomainPolicy: null,
    pct: null,
    reporting: false,
    summary: "No DMARC record was detected.",
  });

  const enforcing = evaluateDmarcPolicy("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com");
  assert.equal(enforcing.status, "strong");
  assert.equal(enforcing.policy, "reject");
  assert.equal(enforcing.subdomainPolicy, "quarantine");
  assert.equal(enforcing.reporting, true);

  const partial = evaluateDmarcPolicy("v=DMARC1; p=quarantine; pct=50");
  assert.equal(partial.status, "watch");
  assert.equal(partial.pct, 50);

  const monitorOnly = evaluateDmarcPolicy("v=DMARC1; p=none; rua=mailto:dmarc@example.com");
  assert.equal(monitorOnly.status, "weak");
  assert.equal(monitorOnly.policy, "none");
});
