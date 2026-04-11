import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
import { CtDiscoveryInfo } from "@/types/analysis";

interface CtDiscoveryPanelProps {
  ctDiscovery: CtDiscoveryInfo;
}

export const CtDiscoveryPanel = ({ ctDiscovery }: CtDiscoveryPanelProps) => {
  const strengthItems = ctDiscovery.strengths.length
    ? ctDiscovery.strengths
    : ["CT enrichment did not add any positive coverage signals for this target."];
  const reviewItems = ctDiscovery.issues.length
    ? ctDiscovery.issues
    : ["No CT-specific review issues were identified."];

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>Certificate Transparency</CardTitle>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-slate-700">
            {ctDiscovery.subdomains.length} discovered
          </div>
        </div>
        <p className="text-sm text-slate-500">
          Passive subdomain discovery from public CT logs. This does not touch the target directly.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm leading-6 text-slate-600">{ctDiscovery.coverageSummary}</p>

        <div className="grid gap-4 md:grid-cols-3">
          <StatBox label="Queried domain" value={<p className="text-lg font-semibold">{ctDiscovery.queriedDomain}</p>} />
          <StatBox label="Distinct subdomains" value={<p className="text-lg font-semibold">{ctDiscovery.subdomains.length}</p>} />
          <StatBox label="Wildcard entries" value={<p className="text-lg font-semibold">{ctDiscovery.wildcardEntries.length}</p>} />
        </div>

        <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Discovered hosts</p>
            {ctDiscovery.subdomains.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {ctDiscovery.subdomains.map((host) => (
                  <span key={host} className="rounded-full bg-white px-3 py-1 text-sm text-slate-700 shadow-sm">
                    {host}
                  </span>
                ))}
              </div>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No distinct subdomains were returned from CT logs for this domain.</p>
            )}
          </div>

          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Wildcard coverage</p>
            {ctDiscovery.wildcardEntries.length > 0 ? (
              <ul className="mt-3 space-y-2 text-sm text-slate-700">
                {ctDiscovery.wildcardEntries.map((entry) => (
                  <li key={entry}>*.{entry}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No wildcard certificate entries were surfaced.</p>
            )}
            <p className="mt-4 text-xs text-slate-500">Source: {ctDiscovery.sourceUrl}</p>
          </div>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Prioritized hosts</p>
            {ctDiscovery.prioritizedHosts.length > 0 ? (
              <ul className="mt-3 space-y-3 text-sm text-slate-700">
                {ctDiscovery.prioritizedHosts.slice(0, 8).map((host) => (
                  <li key={host.host} className="rounded-2xl border border-slate-200 bg-white p-3">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-semibold text-slate-900">{host.host}</span>
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">
                        {host.priority} {host.category}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">{host.evidence}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No high-signal host categories were derived from CT results.</p>
            )}
          </div>

          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Sampled coverage</p>
            {ctDiscovery.sampledHosts.length > 0 ? (
              <ul className="mt-3 space-y-3 text-sm text-slate-700">
                {ctDiscovery.sampledHosts.map((host) => (
                  <li key={host.host} className="rounded-2xl border border-slate-200 bg-white p-3">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-semibold text-slate-900">{host.host}</span>
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">
                        {host.reachable ? `${host.statusCode} ${host.responseKind}` : "unreachable"}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">{host.note}</p>
                    {host.suspectedTakeover ? (
                      <p className="mt-2 text-xs font-medium text-amber-700">
                        Possible takeover: {host.suspectedTakeover.provider} ({host.suspectedTakeover.confidence} confidence)
                      </p>
                    ) : null}
                    {host.cnameTargets.length ? (
                      <p className="mt-2 break-all text-xs text-slate-500">CNAME: {host.cnameTargets.join(", ")}</p>
                    ) : null}
                    {(host.identityProvider || host.edgeProvider) && (
                      <p className="mt-2 text-xs text-slate-600">
                        {host.identityProvider ? `IdP: ${host.identityProvider}` : "IdP: none"}
                        {host.edgeProvider ? ` | Edge: ${host.edgeProvider}` : ""}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No best-effort CT host sampling was recorded.</p>
            )}
          </div>
        </div>

        <div className="grid gap-3 xl:grid-cols-2">
          <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-700">Strengths</p>
            <ul className="mt-3 space-y-2 text-sm text-emerald-900">
              {strengthItems.map((item) => (
                <li key={item} className="flex gap-2">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-amber-700">Review points</p>
            <ul className="mt-3 space-y-2 text-sm text-amber-900">
              {reviewItems.map((item) => (
                <li key={item} className="flex gap-2">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
