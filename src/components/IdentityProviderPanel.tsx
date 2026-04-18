import { ShieldCheck, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
import { IdentityProviderInfo } from "@/types/analysis";

interface IdentityProviderPanelProps {
  identityProvider: IdentityProviderInfo;
}

export const IdentityProviderPanel = ({ identityProvider }: IdentityProviderPanelProps) => {
  const reviewItems = identityProvider.issues;
  const strengthItems = [
    ...(identityProvider.strengths.length
    ? identityProvider.strengths
    : ["No strong identity-provider signals were confirmed from passive evidence."]),
    ...(reviewItems.length === 0 && identityProvider.detected
      ? ["No specific OAuth/OIDC review issues were confirmed from passive evidence alone."]
      : []),
    ...(reviewItems.length === 0 && !identityProvider.detected
      ? ["No passive OAuth review issues were identified."]
      : []),
  ];

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>Identity Provider</CardTitle>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-slate-700">
            {identityProvider.detected ? "Detected" : "Not detected"}
          </div>
        </div>
        <p className="text-sm text-slate-500">
          Passive OAuth and OIDC exposure signals from redirects, login paths, and public well-known endpoints.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatBox label="Provider" value={<p className="text-lg font-semibold">{identityProvider.provider ?? "No obvious provider"}</p>} />
          <StatBox label="Protocol" value={<p className="text-lg font-semibold">{identityProvider.protocol ? identityProvider.protocol.toUpperCase() : "Not inferred"}</p>} />
          <StatBox label="Redirect origins" value={<p className="text-lg font-semibold">{identityProvider.redirectOrigins.length}</p>} />
          <StatBox label="OIDC config" value={<p className="text-sm font-semibold">{identityProvider.openIdConfigurationUrl ? "Publicly reachable" : "Not observed"}</p>} />
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="space-y-3">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Observed endpoints</p>
            <div className="space-y-2 rounded-2xl bg-slate-50 p-4 text-sm text-slate-700">
              <p><span className="font-semibold text-slate-900">Issuer:</span> {identityProvider.issuer ?? "Not discovered"}</p>
              <p><span className="font-semibold text-slate-900">Authorization:</span> {identityProvider.authorizationEndpoint ?? "Not discovered"}</p>
              <p><span className="font-semibold text-slate-900">Token:</span> {identityProvider.tokenEndpoint ?? "Not discovered"}</p>
              <p><span className="font-semibold text-slate-900">End session:</span> {identityProvider.endSessionEndpoint ?? "Not discovered"}</p>
              <p><span className="font-semibold text-slate-900">Tenant brand:</span> {identityProvider.tenantBrand ?? "Not discovered"}</p>
              <p><span className="font-semibold text-slate-900">Tenant region:</span> {identityProvider.tenantRegion ?? "Not discovered"}</p>
            </div>
          </div>

          <div className="space-y-3">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Discovery</p>
            <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-700">
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

        <div className={`grid gap-3 ${reviewItems.length ? "xl:grid-cols-2" : ""}`}>
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
          {reviewItems.length ? (
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
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
};
