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
  <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
    <div className="flex items-center justify-between gap-3">
      <div>
        <h2 className="text-2xl font-bold text-slate-950">Certificate Transparency</h2>
        <p className="mt-1 text-sm text-slate-500">
          Passive subdomain discovery from public CT logs. This does not touch the target directly.
        </p>
      </div>
      <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-slate-700">
        {ctDiscovery.subdomains.length} discovered
      </div>
    </div>

    <p className="mt-4 text-sm leading-6 text-slate-600">{ctDiscovery.coverageSummary}</p>

    <div className="mt-6 grid gap-4 md:grid-cols-3">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Queried domain</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{ctDiscovery.queriedDomain}</p>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Distinct subdomains</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{ctDiscovery.subdomains.length}</p>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Wildcard entries</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{ctDiscovery.wildcardEntries.length}</p>
      </div>
    </div>

    <div className="mt-6 grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Discovered hosts</h3>
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

      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Wildcard coverage</h3>
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

    <div className="mt-6 grid gap-6 xl:grid-cols-2">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Prioritized hosts</h3>
        {ctDiscovery.prioritizedHosts.length > 0 ? (
          <ul className="mt-3 space-y-3 text-sm text-slate-700">
            {ctDiscovery.prioritizedHosts.slice(0, 8).map((host) => (
              <li key={host.host} className="rounded-2xl border border-slate-200 bg-white p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-semibold text-slate-900">{host.host}</span>
                  <span className="text-xs uppercase tracking-[0.12em] text-slate-500">
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

      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Sampled coverage</h3>
        {ctDiscovery.sampledHosts.length > 0 ? (
          <ul className="mt-3 space-y-3 text-sm text-slate-700">
            {ctDiscovery.sampledHosts.map((host) => (
              <li key={host.host} className="rounded-2xl border border-slate-200 bg-white p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-semibold text-slate-900">{host.host}</span>
                  <span className="text-xs uppercase tracking-[0.12em] text-slate-500">
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

    <div className="mt-6 grid gap-3 xl:grid-cols-2">
      <div className="rounded-2xl border border-emerald-100 bg-emerald-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-emerald-700">Strengths</h3>
        <ul className="mt-3 space-y-2 text-sm text-emerald-900">
          {strengthItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
      <div className="rounded-2xl border border-amber-100 bg-amber-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-amber-700">Review points</h3>
        <ul className="mt-3 space-y-2 text-sm text-amber-900">
          {reviewItems.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  </section>
);
};
