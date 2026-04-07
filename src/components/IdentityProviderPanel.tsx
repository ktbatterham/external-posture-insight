import { IdentityProviderInfo } from "@/types/analysis";

interface IdentityProviderPanelProps {
  identityProvider: IdentityProviderInfo;
}

export const IdentityProviderPanel = ({ identityProvider }: IdentityProviderPanelProps) => (
  <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
    <div className="flex items-center justify-between gap-3">
      <div>
        <h2 className="text-2xl font-bold text-slate-950">Identity Provider</h2>
        <p className="mt-1 text-sm text-slate-500">
          Passive OAuth and OIDC exposure signals from redirects, login paths, and public well-known endpoints.
        </p>
      </div>
      <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-slate-700">
        {identityProvider.detected ? "Detected" : "Not detected"}
      </div>
    </div>

    <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Provider</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{identityProvider.provider ?? "No obvious provider"}</p>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Protocol</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{identityProvider.protocol ? identityProvider.protocol.toUpperCase() : "Not inferred"}</p>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Redirect origins</p>
        <p className="mt-2 text-lg font-semibold text-slate-950">{identityProvider.redirectOrigins.length}</p>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">OIDC config</p>
        <p className="mt-2 text-sm font-semibold text-slate-950">
          {identityProvider.openIdConfigurationUrl ? "Publicly reachable" : "Not observed"}
        </p>
      </div>
    </div>

    <div className="mt-6 grid gap-6 xl:grid-cols-2">
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Observed endpoints</h3>
        <div className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          <p><span className="font-semibold text-slate-900">Issuer:</span> {identityProvider.issuer ?? "Not discovered"}</p>
          <p><span className="font-semibold text-slate-900">Authorization:</span> {identityProvider.authorizationEndpoint ?? "Not discovered"}</p>
          <p><span className="font-semibold text-slate-900">Token:</span> {identityProvider.tokenEndpoint ?? "Not discovered"}</p>
          <p><span className="font-semibold text-slate-900">End session:</span> {identityProvider.endSessionEndpoint ?? "Not discovered"}</p>
          <p><span className="font-semibold text-slate-900">Tenant brand:</span> {identityProvider.tenantBrand ?? "Not discovered"}</p>
          <p><span className="font-semibold text-slate-900">Tenant region:</span> {identityProvider.tenantRegion ?? "Not discovered"}</p>
        </div>
      </div>

      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Discovery</h3>
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          {identityProvider.redirectOrigins.length > 0 && (
            <div className="mb-3">
              <p className="font-semibold text-slate-900">Redirect origins</p>
              <ul className="mt-2 space-y-1">
                {identityProvider.redirectOrigins.map((origin) => (
                  <li key={origin}>{origin}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.authHostCandidates.length > 0 && (
            <div className="mb-3">
              <p className="font-semibold text-slate-900">Auth-like hosts</p>
              <ul className="mt-2 space-y-1">
                {identityProvider.authHostCandidates.map((host) => (
                  <li key={host}>{host}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.loginPaths.length > 0 && (
            <div className="mb-3">
              <p className="font-semibold text-slate-900">Login-like paths</p>
              <ul className="mt-2 space-y-1">
                {identityProvider.loginPaths.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.wellKnownEndpoints.length > 0 && (
            <div className="mb-3">
              <p className="font-semibold text-slate-900">Well-known endpoints</p>
              <ul className="mt-2 space-y-1 break-all">
                {identityProvider.wellKnownEndpoints.map((endpoint) => (
                  <li key={endpoint}>{endpoint}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.tenantSignals.length > 0 && (
            <div>
              <p className="font-semibold text-slate-900">Tenant clues</p>
              <ul className="mt-2 space-y-1">
                {identityProvider.tenantSignals.map((signal) => (
                  <li key={signal}>{signal}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.redirectUriSignals.length > 0 && (
            <div>
              <p className="font-semibold text-slate-900">Public redirect URI signals</p>
              <ul className="mt-2 space-y-1">
                {identityProvider.redirectUriSignals.map((signal) => (
                  <li key={signal}>{signal}</li>
                ))}
              </ul>
            </div>
          )}
          {identityProvider.redirectOrigins.length === 0 &&
            identityProvider.authHostCandidates.length === 0 &&
            identityProvider.loginPaths.length === 0 &&
            identityProvider.redirectUriSignals.length === 0 && <p>No passive IdP or OAuth discovery artifacts were recorded.</p>}
        </div>
      </div>
    </div>

    <div className="mt-6 grid gap-3 xl:grid-cols-2">
      <div className="rounded-2xl border border-emerald-100 bg-emerald-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-emerald-700">Strengths</h3>
        <ul className="mt-3 space-y-2 text-sm text-emerald-900">
          {(identityProvider.strengths.length ? identityProvider.strengths : ["No identity-provider strengths recorded yet."]).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
      <div className="rounded-2xl border border-amber-100 bg-amber-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-amber-700">Review points</h3>
        <ul className="mt-3 space-y-2 text-sm text-amber-900">
          {(identityProvider.issues.length ? identityProvider.issues : ["No passive OAuth review issues were identified."]).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>
    </div>
  </section>
);
