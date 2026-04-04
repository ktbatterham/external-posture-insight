import { getAiSurfaceClassificationSummary } from "@/lib/aiSurface";
import { AnalysisResult } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";
import { getPriorityActions } from "@/lib/priorities";
import { getDisclosurePosture, getDominantThemes } from "@/lib/reportInsights";

const buildExposureLines = (analysis: AnalysisResult) =>
  analysis.exposure.probes.map(
    (probe) => `- ${probe.label} (${probe.path}): ${probe.finding} (${probe.statusCode}) - ${probe.detail}`,
  );

const buildTechnologyLines = (analysis: AnalysisResult) =>
  analysis.technologies.length
    ? analysis.technologies.map(
        (tech) =>
          `- ${tech.name} (${tech.category}, ${tech.detection}, ${tech.confidence} confidence)${tech.evidence ? `: ${tech.evidence}` : ""}`,
      )
    : ["- No stack signals recorded."];

const buildDiscoveryLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.firstPartyPaths.length
    ? analysis.htmlSecurity.firstPartyPaths.map((path) => `- Path: ${path}`)
    : ["- No same-origin paths discovered from the fetched page."];

const buildPassiveLeakLines = (analysis: AnalysisResult) =>
  analysis.htmlSecurity.passiveLeakSignals.length
    ? analysis.htmlSecurity.passiveLeakSignals.map(
        (signal) => `- [${signal.severity}] ${signal.title}: ${signal.detail}${signal.evidence.length ? ` Evidence: ${signal.evidence.join(", ")}` : ""}`,
      )
    : ["- No passive leak or fingerprinting signals recorded."];

const buildThirdPartyLines = (analysis: AnalysisResult) =>
  analysis.thirdPartyTrust.providers.length
    ? analysis.thirdPartyTrust.providers.map(
        (provider) => `- ${provider.name} [${provider.category} | ${provider.risk} risk] ${provider.domain}`,
      )
    : ["- No third-party providers recorded."];

export const buildMarkdownReport = (analysis: AnalysisResult) => {
  const areas = getAreaScores(analysis);
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const aiSummary = getAiSurfaceClassificationSummary(analysis.aiSurface);
  const taxonomy = getDominantThemes(analysis);
  const disclosure = getDisclosurePosture(analysis);

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
    "## Risk Themes",
    "",
    `- Summary: ${taxonomy.summary}`,
    ...(taxonomy.owasp.length ? taxonomy.owasp.map((item) => `- OWASP: ${item.label} (${item.count})`) : ["- No OWASP themes recorded."]),
    ...(taxonomy.mitre.length ? taxonomy.mitre.map((item) => `- MITRE: ${item.label} (${item.count})`) : ["- No MITRE themes recorded."]),
    "",
    "## Category Scores",
    "",
    "- These category scores are directional breakdowns by posture area. They explain where risk is concentrated, but they are not intended to exactly match the single overall score.",
    "",
    ...areas.map((area) => `- ${area.label}: ${area.score}/100 (${area.status})`),
    "",
    "## Key Findings",
    "",
    ...(analysis.issues.length
      ? analysis.issues.map(
          (issue) =>
            `- [${issue.severity} | ${issue.confidence} confidence | ${issue.source}${issue.owasp.length ? ` | OWASP: ${issue.owasp.join(", ")}` : ""}${issue.mitre.length ? ` | MITRE: ${issue.mitre.join(", ")}` : ""}] ${issue.title}: ${issue.detail}`,
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
    "## Disclosure & Trust",
    "",
    `- Summary: ${disclosure.summary}`,
    ...(disclosure.discoveredPages.length
      ? disclosure.discoveredPages.map((page) => `- Discovered page: ${page}`)
      : ["- No obvious trust or policy pages discovered."]),
    ...disclosure.strengths.map((item) => `- ${item}`),
    ...disclosure.issues.map((item) => `- ${item}`),
    "",
    "## Passive Discovery",
    "",
    `- Page title: ${analysis.htmlSecurity.pageTitle ?? "Unavailable"}`,
    `- Discovery sources: ${analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded"}`,
    `- Same-origin paths discovered: ${analysis.htmlSecurity.firstPartyPaths.length}`,
    ...buildDiscoveryLines(analysis),
    ...buildPassiveLeakLines(analysis),
    "",
    "## Detected Stack",
    "",
    ...buildTechnologyLines(analysis),
    "",
    "## Third-Party Trust",
    "",
    `- Providers detected: ${analysis.thirdPartyTrust.totalProviders}`,
    `- Higher-risk providers: ${analysis.thirdPartyTrust.highRiskProviders}`,
    `- Summary: ${analysis.thirdPartyTrust.summary}`,
    ...buildThirdPartyLines(analysis),
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
    ...buildExposureLines(analysis),
    "",
  ].join("\n");
};

export const buildHtmlReport = (analysis: AnalysisResult) => {
  const areas = getAreaScores(analysis);
  const summary = getUnifiedIssueSummary(analysis);
  const priorityActions = getPriorityActions(analysis);
  const aiSummary = getAiSurfaceClassificationSummary(analysis.aiSurface);
  const taxonomy = getDominantThemes(analysis);
  const disclosure = getDisclosurePosture(analysis);
  const issueItems = analysis.issues.length
    ? analysis.issues
        .map(
          (issue) =>
            `<li><strong>[${issue.severity} | ${issue.confidence} confidence | ${issue.source}${issue.owasp.length ? ` | OWASP: ${issue.owasp.join(", ")}` : ""}${issue.mitre.length ? ` | MITRE: ${issue.mitre.join(", ")}` : ""}] ${issue.title}</strong><br>${issue.detail}</li>`,
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
  const exposureItems = buildExposureLines(analysis)
    .map((line) => `<li>${line.slice(2)}</li>`)
    .join("");
  const technologyItems = analysis.technologies.length
    ? analysis.technologies
        .map(
          (tech) =>
            `<li><strong>${tech.name}</strong> (${tech.category}, ${tech.detection}, ${tech.confidence} confidence)<br>${tech.evidence}</li>`,
        )
        .join("")
    : "<li>No stack signals recorded.</li>";
  const discoveryItems = analysis.htmlSecurity.firstPartyPaths.length
    ? analysis.htmlSecurity.firstPartyPaths.map((path) => `<li>${path}</li>`).join("")
    : "<li>No same-origin paths discovered from the fetched page.</li>";
  const passiveLeakItems = buildPassiveLeakLines(analysis)
    .map((line) => `<li>${line.slice(2)}</li>`)
    .join("");

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
      <h2>Risk Themes</h2>
      <p>${taxonomy.summary}</p>
      <ul>
        ${taxonomy.owasp.length ? taxonomy.owasp.map((item) => `<li>OWASP: ${item.label} (${item.count})</li>`).join("") : "<li>No OWASP themes recorded.</li>"}
        ${taxonomy.mitre.length ? taxonomy.mitre.map((item) => `<li>MITRE: ${item.label} (${item.count})</li>`).join("") : "<li>No MITRE themes recorded.</li>"}
      </ul>
    </div>
    <div class="card">
      <h2>Category Scores</h2>
      <p>These category scores are directional breakdowns by posture area. They explain where risk is concentrated, but they are not intended to exactly match the single overall score.</p>
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
      <h2>Disclosure & Trust</h2>
      <p>${disclosure.summary}</p>
      <ul>
        ${disclosure.discoveredPages.length ? disclosure.discoveredPages.map((item) => `<li>Discovered page: ${item}</li>`).join("") : "<li>No obvious trust or policy pages discovered.</li>"}
        ${disclosure.strengths.map((item) => `<li>${item}</li>`).join("")}
        ${disclosure.issues.map((item) => `<li>${item}</li>`).join("")}
      </ul>
    </div>
    <div class="card">
      <h2>Passive Discovery</h2>
      <p>Page title: ${analysis.htmlSecurity.pageTitle ?? "Unavailable"}</p>
      <p>Discovery sources: ${analysis.crawl.discoverySources.length ? analysis.crawl.discoverySources.join(", ") : "None recorded"}</p>
      <ul>${discoveryItems}</ul>
      <p>Passive leak and fingerprinting signals:</p>
      <ul>${passiveLeakItems}</ul>
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
