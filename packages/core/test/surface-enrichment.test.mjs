import assert from "node:assert/strict";
import test from "node:test";
import { analyzeExposure } from "../dist/surfaceEnrichment.js";

test("analyzeExposure does not treat SPA shell fallbacks as exposed sensitive files", async () => {
  const finalUrl = new URL("https://example.com/");
  const htmlShell = "<html><head><title>Example App</title></head><body><div id=\"root\"></div></body></html>";

  const summary = await analyzeExposure(
    finalUrl,
    {
      signature: "Example App|root",
      pageTitle: "Example App",
    },
    {
      exposureProbes: [
        { label: "Git metadata", path: "/.git/HEAD" },
        { label: "Environment file", path: "/.env" },
      ],
      requestOnce: async (targetUrl) => ({
        statusCode: targetUrl.pathname === "/.git/HEAD" || targetUrl.pathname === "/.env" ? 200 : 404,
        headers: {
          "content-type": "text/html; charset=utf-8",
        },
        elapsedMs: 5,
      }),
      requestText: async () => ({
        statusCode: 200,
        headers: {
          "content-type": "text/html; charset=utf-8",
        },
        body: htmlShell,
      }),
      fetchWithRedirects: async (targetUrl) => ({
        finalUrl: targetUrl,
        response: {
          statusCode: 404,
          headers: {},
          elapsedMs: 5,
        },
      }),
      headerValue: (headers, name) => {
        const value = headers[name] ?? headers[name.toLowerCase()];
        return Array.isArray(value) ? value[0] ?? null : value ?? null;
      },
      formatErrorMessage: (error) => (error instanceof Error ? error.message : "Probe failed"),
      isAccessDeniedHtml: () => false,
      classifyHtmlApiFallback: (_probePath, _finalUrl, _resolvedUrl, body, homepageSignature, homepageTitle) =>
        body.includes("id=\"root\"") &&
        homepageSignature === "Example App|root" &&
        homepageTitle === "Example App",
    },
  );

  assert.equal(summary.issues.length, 0);
  assert.equal(summary.probes[0].finding, "interesting");
  assert.match(summary.probes[0].detail, /frontend shell/i);
  assert.match(summary.strengths.at(-1), /frontend shell/i);
});
