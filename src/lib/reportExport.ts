import { AnalysisResult } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";
import { getPriorityActions } from "@/lib/priorities";

export const buildMarkdownReport = (analysis: AnalysisResult) => {
  const areas = getAreaScores(analysis);
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const hasAiVendor = analysis.aiSurface.vendors.some((vendor) => vendor.category === "ai_vendor");
  const hasAutomationVendor = analysis.aiSurface.vendors.some((vendor) => vendor.category === "support_automation");
  const hasAssistantUi =
    analysis.aiSurface.assistantVisible ||
    analysis.aiSurface.vendors.some((vendor) => vendor.category === "assistant_ui");
  const aiSummary = !analysis.aiSurface.detected
    ? "No visible AI or automation surface detected"
    : hasAiVendor
      ? "AI vendor signals detected"
      : hasAssistantUi
        ? "Assistant UI signals detected"
        : hasAutomationVendor
          ? "Support automation signals detected"
          : "AI-adjacent signals detected";

  return [
    `# Security Report: ${analysis.host}`,
    "",
    `- Final URL: ${analysis.finalUrl}`,
    `- Scanned: ${new Date(analysis.scannedAt).toLocaleString()}`,
    `- Grade: ${analysis.grade}`,
    `- Score: ${analysis.score}/100`,
    `- Status: ${analysis.statusCode}`,
    "",
    "## Executive Readout",
    "",
    `- Overview: ${analysis.executiveSummary.overview}`,
    `- Main risk: ${analysis.executiveSummary.mainRisk}`,
    ...analysis.executiveSummary.takeaways.map((takeaway) => `- ${takeaway}`),
    "",
    "## Summary",
    "",
    `- Critical findings: ${summary.critical}`,
    `- Warning findings: ${summary.warning}`,
    `- Informational findings: ${summary.info}`,
    "",
    "## Area Scores",
    "",
    ...areas.map((area) => `- ${area.label}: ${area.score}/100 (${area.status})`),
    "",
    "## Key Findings",
    "",
    ...(analysis.issues.length
      ? analysis.issues.map(
          (issue) =>
            `- [${issue.severity} | ${issue.confidence} confidence | ${issue.source}] ${issue.title}: ${issue.detail}`,
        )
      : ["- No core findings recorded."]),
    "",
    "## Priority Actions",
    "",
    ...(priorityActions.length
      ? priorityActions.map((action, index) => `- ${index + 1}. [${action.severity}] ${action.title}: ${action.detail}`)
      : ["- No priority actions generated."]),
    "",
    "## security.txt",
    "",
    `- Status: ${analysis.securityTxt.status}`,
    ...(analysis.securityTxt.url ? [`- URL: ${analysis.securityTxt.url}`] : []),
    ...(analysis.securityTxt.issues.length ? analysis.securityTxt.issues.map((issue) => `- ${issue}`) : ["- No security.txt issues recorded."]),
    "",
    "## Domain & Email Security",
    "",
    `- SPF: ${analysis.domainSecurity.spf ?? "Not found"}`,
    `- DMARC: ${analysis.domainSecurity.dmarc ?? "Not found"}`,
    `- MX count: ${analysis.domainSecurity.mxRecords.length}`,
    `- CAA count: ${analysis.domainSecurity.caaRecords.length}`,
    "",
    "## Public Trust Signals",
    "",
    `- HSTS preload status: ${analysis.publicSignals.hstsPreload.status}`,
    `- HSTS preload note: ${analysis.publicSignals.hstsPreload.summary}`,
    "",
    "## Passive Discovery",
    "",
    `- Page title: ${analysis.htmlSecurity.pageTitle ?? "Unavailable"}`,
    `- Discovery sources: ${analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded"}`,
    `- Same-origin paths discovered: ${analysis.htmlSecurity.firstPartyPaths.length}`,
    ...(analysis.htmlSecurity.firstPartyPaths.length
      ? analysis.htmlSecurity.firstPartyPaths.map((path) => `- Path: ${path}`)
      : ["- No same-origin paths discovered from the fetched page."]),
    "",
    "## Detected Stack",
    "",
    ...(analysis.technologies.length
      ? analysis.technologies.map((tech) => `- ${tech.name} (${tech.category})${tech.evidence ? `: ${tech.evidence}` : ""}`)
      : ["- No stack signals recorded."]),
    "",
    "## Third-Party Trust",
    "",
    `- Providers detected: ${analysis.thirdPartyTrust.totalProviders}`,
    `- Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}`,
    `- Summary: ${analysis.thirdPartyTrust.summary}`,
    ...(analysis.thirdPartyTrust.providers.length
      ? analysis.thirdPartyTrust.providers.map((provider) => `- ${provider.name} [${provider.category} | ${provider.risk} risk] ${provider.domain}`)
      : ["- No third-party providers recorded."]),
    ...(analysis.thirdPartyTrust.issues.length
      ? analysis.thirdPartyTrust.issues.map((issue) => `- ${issue}`)
      : ["- No third-party trust issues recorded."]),
    "",
    "## AI Surface",
    "",
    `- Classification: ${aiSummary}`,
    `- AI detected: ${analysis.aiSurface.detected ? "Yes" : "No"}`,
    `- Assistant visible: ${analysis.aiSurface.assistantVisible ? "Yes" : "No"}`,
    `- Vendors: ${analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected"}`,
    `- AI paths: ${analysis.aiSurface.discoveredPaths.length ? analysis.aiSurface.discoveredPaths.join(", ") : "None detected"}`,
    ...(analysis.aiSurface.privacySignals.length ? analysis.aiSurface.privacySignals.map((signal) => `- ${signal}`) : ["- No explicit AI privacy guidance detected."]),
    ...(analysis.aiSurface.governanceSignals.length ? analysis.aiSurface.governanceSignals.map((signal) => `- ${signal}`) : ["- No explicit AI governance language detected."]),
    ...(analysis.aiSurface.issues.length ? analysis.aiSurface.issues.map((issue) => `- ${issue}`) : ["- No AI-surface issues recorded."]),
    "",
    "## Low-Noise Exposure Checks",
    "",
    ...analysis.exposure.probes.map(
      (probe) => `- ${probe.label} (${probe.path}): ${probe.finding} (${probe.statusCode}) - ${probe.detail}`,
    ),
    "",
  ].join("\n");
};

export const buildHtmlReport = (analysis: AnalysisResult) => {
  const areas = getAreaScores(analysis);
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const hasAiVendor = analysis.aiSurface.vendors.some((vendor) => vendor.category === "ai_vendor");
  const hasAutomationVendor = analysis.aiSurface.vendors.some((vendor) => vendor.category === "support_automation");
  const hasAssistantUi =
    analysis.aiSurface.assistantVisible ||
    analysis.aiSurface.vendors.some((vendor) => vendor.category === "assistant_ui");
  const aiSummary = !analysis.aiSurface.detected
    ? "No visible AI or automation surface detected"
    : hasAiVendor
      ? "AI vendor signals detected"
      : hasAssistantUi
        ? "Assistant UI signals detected"
        : hasAutomationVendor
          ? "Support automation signals detected"
          : "AI-adjacent signals detected";
  const issueItems = analysis.issues.length
    ? analysis.issues
        .map(
          (issue) =>
            `<li><strong>[${issue.severity} | ${issue.confidence} confidence | ${issue.source}] ${issue.title}</strong><br>${issue.detail}</li>`,
        )
        .join("")
    : "<li>No core findings recorded.</li>";
  const areaItems = areas
    .map((area) => `<li><strong>${area.label}</strong>: ${area.score}/100 (${area.status})</li>`)
    .join("");
  const priorityItems = priorityActions.length
    ? priorityActions
        .map((action) => `<li><strong>[${action.severity}] ${action.title}</strong><br>${action.detail}</li>`)
        .join("")
    : "<li>No priority actions generated.</li>";
  const exposureItems = analysis.exposure.probes
    .map(
      (probe) =>
        `<li><strong>${probe.label}</strong> (${probe.path}): ${probe.finding} (${probe.statusCode}) - ${probe.detail}</li>`,
    )
    .join("");
  const technologyItems = analysis.technologies.length
    ? analysis.technologies
        .map((tech) => `<li><strong>${tech.name}</strong> (${tech.category})<br>${tech.evidence}</li>`)
        .join("")
    : "<li>No stack signals recorded.</li>";
  const discoveryItems = analysis.htmlSecurity.firstPartyPaths.length
    ? analysis.htmlSecurity.firstPartyPaths.map((path) => `<li>${path}</li>`).join("")
    : "<li>No same-origin paths discovered from the fetched page.</li>";

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Security Report - ${analysis.host}</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 40px; color: #0f172a; }
      h1, h2 { margin-bottom: 8px; }
      .meta, .card { margin-bottom: 24px; }
      .card { border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; background: #f8fafc; }
      ul { line-height: 1.6; }
    </style>
  </head>
  <body>
    <h1>Security Report: ${analysis.host}</h1>
    <div class="meta">
      <p>Final URL: ${analysis.finalUrl}</p>
      <p>Scanned: ${new Date(analysis.scannedAt).toLocaleString()}</p>
      <p>Grade: ${analysis.grade}</p>
      <p>Score: ${analysis.score}/100</p>
      <p>Status: ${analysis.statusCode}</p>
    </div>
    <div class="card">
      <h2>Executive Readout</h2>
      <p>${analysis.executiveSummary.overview}</p>
      <p><strong>Main risk:</strong> ${analysis.executiveSummary.mainRisk}</p>
      <ul>${analysis.executiveSummary.takeaways.map((takeaway) => `<li>${takeaway}</li>`).join("")}</ul>
    </div>
    <div class="card">
      <h2>Summary</h2>
      <p>Critical findings: ${summary.critical}</p>
      <p>Warning findings: ${summary.warning}</p>
      <p>Informational findings: ${summary.info}</p>
    </div>
    <div class="card">
      <h2>Area Scores</h2>
      <ul>${areaItems}</ul>
    </div>
    <div class="card">
      <h2>Key Findings</h2>
      <ul>${issueItems}</ul>
    </div>
    <div class="card">
      <h2>Priority Actions</h2>
      <ul>${priorityItems}</ul>
    </div>
    <div class="card">
      <h2>Public Trust Signals</h2>
      <p>HSTS preload status: ${analysis.publicSignals.hstsPreload.status}</p>
      <p>${analysis.publicSignals.hstsPreload.summary}</p>
    </div>
    <div class="card">
      <h2>Passive Discovery</h2>
      <p>Page title: ${analysis.htmlSecurity.pageTitle ?? "Unavailable"}</p>
      <p>Discovery sources: ${analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded"}</p>
      <ul>${discoveryItems}</ul>
    </div>
    <div class="card">
      <h2>Detected Stack</h2>
      <ul>${technologyItems}</ul>
    </div>
    <div class="card">
      <h2>Third-Party Trust</h2>
      <p>${analysis.thirdPartyTrust.summary}</p>
      <p>Providers detected: ${analysis.thirdPartyTrust.totalProviders}</p>
      <p>Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}</p>
      <ul>${analysis.thirdPartyTrust.providers.length
        ? analysis.thirdPartyTrust.providers.map((provider) => `<li><strong>${provider.name}</strong> [${provider.category} | ${provider.risk} risk] ${provider.domain}<br>${provider.evidence}</li>`).join("")
        : "<li>No third-party providers recorded.</li>"}</ul>
    </div>
    <div class="card">
      <h2>AI Surface</h2>
      <p>Classification: ${aiSummary}</p>
      <p>AI detected: ${analysis.aiSurface.detected ? "Yes" : "No"}</p>
      <p>Assistant visible: ${analysis.aiSurface.assistantVisible ? "Yes" : "No"}</p>
      <p>Vendors: ${analysis.aiSurface.vendors.length ? analysis.aiSurface.vendors.map((vendor) => vendor.name).join(", ") : "None detected"}</p>
      <p>AI paths: ${analysis.aiSurface.discoveredPaths.length ? analysis.aiSurface.discoveredPaths.join(", ") : "None detected"}</p>
      <p>AI privacy signals: ${analysis.aiSurface.privacySignals.length ? analysis.aiSurface.privacySignals.join(" ") : "None detected"}</p>
      <p>AI governance signals: ${analysis.aiSurface.governanceSignals.length ? analysis.aiSurface.governanceSignals.join(" ") : "None detected"}</p>
    </div>
    <div class="card">
      <h2>Low-Noise Exposure Checks</h2>
      <ul>${exposureItems}</ul>
    </div>
  </body>
</html>`;
};
