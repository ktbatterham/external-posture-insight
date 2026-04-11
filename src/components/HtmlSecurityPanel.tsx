import { CodeXml, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { HtmlSecurityInfo } from "@/types/analysis";

interface HtmlSecurityPanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const HtmlSecurityPanel = ({ htmlSecurity }: HtmlSecurityPanelProps) => {
  const warningLeakSignals = htmlSecurity.passiveLeakSignals.filter((signal) => signal.severity === "warning");

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CodeXml className="h-5 w-5" />
          Passive Page Inspection
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-8">
          <StatBox label="Page title" value={<p className="line-clamp-2 text-sm font-semibold">{htmlSecurity.pageTitle || "Unavailable"}</p>} />
          <StatBox label="Forms" value={<p className="text-2xl font-semibold">{htmlSecurity.forms.length}</p>} />
          <StatBox label="External script domains" value={<p className="text-2xl font-semibold">{htmlSecurity.externalScriptDomains.length}</p>} />
          <StatBox label="Same-site hosts" value={<p className="text-2xl font-semibold">{htmlSecurity.sameSiteHosts.length}</p>} />
          <StatBox label="Inline scripts" value={<p className="text-2xl font-semibold">{htmlSecurity.inlineScriptCount}</p>} />
          <StatBox label="Missing SRI" value={<p className="text-2xl font-semibold">{htmlSecurity.missingSriScriptUrls.length}</p>} />
          <StatBox
            label="Passive leak signals"
            value={<p className="text-2xl font-semibold">{htmlSecurity.passiveLeakSignals.length}</p>}
            note={warningLeakSignals.length ? (
              <p className="text-xs text-amber-700">{warningLeakSignals.length} higher-priority review item{warningLeakSignals.length === 1 ? "" : "s"}</p>
            ) : null}
          />
          <StatBox
            label="Library risk signals"
            value={<p className="text-2xl font-semibold">{htmlSecurity.libraryRiskSignals.length}</p>}
            note={htmlSecurity.libraryFingerprints.length ? (
              <p className="text-xs text-slate-500">{htmlSecurity.libraryFingerprints.length} versioned client librar{htmlSecurity.libraryFingerprints.length === 1 ? "y" : "ies"} observed</p>
            ) : null}
          />
        </div>

        {(htmlSecurity.metaGenerator || htmlSecurity.firstPartyPaths.length > 0 || htmlSecurity.sameSiteHosts.length > 0) && (
          <div className="grid gap-4 md:grid-cols-3">
            <StatBox label="Meta generator" value={<p className="text-sm font-medium text-slate-800">{htmlSecurity.metaGenerator || "Not declared"}</p>} />
            <StatBox
              label="Discovered same-origin paths"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.firstPartyPaths.length ? (
                    htmlSecurity.firstPartyPaths.map((path) => (
                      <Badge key={path} variant="outline">{path}</Badge>
                    ))
                  ) : (
                    <span className="text-sm text-slate-500">No same-origin page links were discovered passively.</span>
                  )}
                </div>
              }
            />
            <StatBox
              label="Referenced same-site hosts"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.sameSiteHosts.length ? (
                    htmlSecurity.sameSiteHosts.map((host) => (
                      <Badge key={host} variant="outline">{host}</Badge>
                    ))
                  ) : (
                    <span className="text-sm text-slate-500">No sibling same-site hosts were referenced by the fetched page.</span>
                  )}
                </div>
              }
            />
          </div>
        )}

        {htmlSecurity.forms.length > 0 && (
          <StatBox
            label="Forms"
            value={
              <div className="space-y-2">
                {htmlSecurity.forms.map((form, index) => (
                  <div key={`${form.action ?? "self"}-${index}`} className="rounded-xl bg-white p-3 text-sm text-slate-700">
                    <p>Method: {form.method}</p>
                    <p>Action: {form.action ?? "(same page)"}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {form.hasPasswordField && <Badge variant="secondary">Password field</Badge>}
                      {form.insecureSubmission && <Badge variant="destructive">Insecure submit</Badge>}
                    </div>
                  </div>
                ))}
              </div>
            }
          />
        )}

        {(htmlSecurity.externalScriptDomains.length > 0 || htmlSecurity.externalStylesheetDomains.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <StatBox
              label="Third-party scripts"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.externalScriptDomains.map((domain) => (
                    <Badge key={domain} variant="outline">{domain}</Badge>
                  ))}
                </div>
              }
            />
            <StatBox
              label="Third-party stylesheets"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.externalStylesheetDomains.map((domain) => (
                    <Badge key={domain} variant="outline">{domain}</Badge>
                  ))}
                </div>
              }
            />
          </div>
        )}

        {htmlSecurity.passiveLeakSignals.length > 0 && (
          <StatBox
            label="Passive leak and fingerprinting signals"
            value={
              <div className="space-y-3">
                {htmlSecurity.passiveLeakSignals.map((signal) => (
                  <div key={`${signal.category}-${signal.title}`} className="rounded-xl bg-white p-4 text-sm text-slate-700">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-semibold text-slate-950">{signal.title}</p>
                      <Badge variant={signal.severity === "warning" ? "destructive" : "secondary"}>
                        {signal.severity}
                      </Badge>
                    </div>
                    <p className="mt-2">{signal.detail}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {signal.evidence.map((item) => (
                        <Badge key={item} variant="outline">{item}</Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            }
          />
        )}

        {(htmlSecurity.libraryFingerprints.length > 0 || htmlSecurity.libraryRiskSignals.length > 0) && (
          <StatBox
            label="Library version risk"
            value={
              <div className="space-y-3">
                {htmlSecurity.libraryRiskSignals.length ? (
                  htmlSecurity.libraryRiskSignals.map((signal) => (
                    <div key={`${signal.packageName}-${signal.version}`} className="rounded-xl bg-white p-4 text-sm text-slate-700">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="font-semibold text-slate-950">
                          {signal.packageName} {signal.version}
                        </p>
                        <Badge variant="secondary">{signal.confidence} confidence</Badge>
                        <Badge variant="destructive">
                          {signal.vulnerabilities.length} advisor{signal.vulnerabilities.length === 1 ? "y" : "ies"}
                        </Badge>
                      </div>
                      <p className="mt-2 text-slate-600">{signal.evidence}</p>
                      <p className="mt-1 break-all text-xs text-slate-500">{signal.sourceUrl}</p>
                      <div className="mt-3 space-y-2">
                        {signal.vulnerabilities.map((item) => (
                          <div key={item.id} className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2">
                            <p className="font-medium text-slate-900">
                              {item.id}
                              {item.aliases.length ? ` • ${item.aliases.join(", ")}` : ""}
                            </p>
                            <p className="mt-1 text-slate-700">{item.summary}</p>
                            <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">Severity: {item.severity}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-xl bg-white p-4 text-sm text-slate-700">
                    Explicitly versioned client libraries were detected, but no matching OSV advisories were returned.
                  </div>
                )}
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {htmlSecurity.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {htmlSecurity.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
