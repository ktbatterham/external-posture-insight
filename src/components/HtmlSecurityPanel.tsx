import { CodeXml, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Page title</p>
            <p className="mt-2 line-clamp-2 text-sm font-semibold text-slate-950">
              {htmlSecurity.pageTitle || "Unavailable"}
            </p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Forms</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.forms.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">External script domains</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.externalScriptDomains.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Same-site hosts</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.sameSiteHosts.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Inline scripts</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.inlineScriptCount}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Missing SRI</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.missingSriScriptUrls.length}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Passive leak signals</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.passiveLeakSignals.length}</p>
            {warningLeakSignals.length ? (
              <p className="mt-1 text-xs text-amber-700">{warningLeakSignals.length} higher-priority review item{warningLeakSignals.length === 1 ? "" : "s"}</p>
            ) : null}
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Library risk signals</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{htmlSecurity.libraryRiskSignals.length}</p>
            {htmlSecurity.libraryFingerprints.length ? (
              <p className="mt-1 text-xs text-slate-500">{htmlSecurity.libraryFingerprints.length} versioned client librar{htmlSecurity.libraryFingerprints.length === 1 ? "y" : "ies"} observed</p>
            ) : null}
          </div>
        </div>

        {(htmlSecurity.metaGenerator || htmlSecurity.firstPartyPaths.length > 0 || htmlSecurity.sameSiteHosts.length > 0) && (
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Meta generator</p>
              <p className="mt-2 text-sm font-medium text-slate-800">{htmlSecurity.metaGenerator || "Not declared"}</p>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Discovered same-origin paths</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.firstPartyPaths.length ? (
                  htmlSecurity.firstPartyPaths.map((path) => (
                    <Badge key={path} variant="outline">{path}</Badge>
                  ))
                ) : (
                  <span className="text-sm text-slate-500">No same-origin page links were discovered passively.</span>
                )}
              </div>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Referenced same-site hosts</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.sameSiteHosts.length ? (
                  htmlSecurity.sameSiteHosts.map((host) => (
                    <Badge key={host} variant="outline">{host}</Badge>
                  ))
                ) : (
                  <span className="text-sm text-slate-500">No sibling same-site hosts were referenced by the fetched page.</span>
                )}
              </div>
            </div>
          </div>
        )}

        {htmlSecurity.forms.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Forms</p>
            <div className="mt-3 space-y-2">
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
          </div>
        )}

        {(htmlSecurity.externalScriptDomains.length > 0 || htmlSecurity.externalStylesheetDomains.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Third-party scripts</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.externalScriptDomains.map((domain) => (
                  <Badge key={domain} variant="outline">{domain}</Badge>
                ))}
              </div>
            </div>
            <div className="rounded-2xl bg-slate-50 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Third-party stylesheets</p>
              <div className="mt-3 flex flex-wrap gap-2">
                {htmlSecurity.externalStylesheetDomains.map((domain) => (
                  <Badge key={domain} variant="outline">{domain}</Badge>
                ))}
              </div>
            </div>
          </div>
        )}

        {htmlSecurity.passiveLeakSignals.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Passive leak and fingerprinting signals</p>
            <div className="mt-3 space-y-3">
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
          </div>
        )}

        {(htmlSecurity.libraryFingerprints.length > 0 || htmlSecurity.libraryRiskSignals.length > 0) && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Library version risk</p>
            <div className="mt-3 space-y-3">
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
          </div>
        )}

        <div className="space-y-2">
          {htmlSecurity.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {htmlSecurity.issues.map((issue) => (
            <div key={issue} className="flex gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{issue}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
