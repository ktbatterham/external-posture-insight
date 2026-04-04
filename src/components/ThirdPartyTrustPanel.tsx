import { Boxes, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThirdPartyTrustInfo } from "@/types/analysis";

interface ThirdPartyTrustPanelProps {
  thirdPartyTrust: ThirdPartyTrustInfo;
}

const riskStyles = {
  low: "bg-emerald-100 text-emerald-900",
  medium: "bg-amber-100 text-amber-900",
  high: "bg-rose-100 text-rose-900",
} as const;

const categoryLabel = {
  analytics: "Analytics",
  consent: "Consent",
  support: "Support",
  ai: "AI",
  session_replay: "Session replay",
  payments: "Payments",
  social: "Social",
  ads: "Ads",
  cdn: "CDN",
  security: "Security",
  other: "Other",
} as const;

export const ThirdPartyTrustPanel = ({ thirdPartyTrust }: ThirdPartyTrustPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Boxes className="h-5 w-5" />
          Third-Party Trust
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <p className="text-sm text-slate-700">{thirdPartyTrust.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Providers</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{thirdPartyTrust.totalProviders}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">High risk</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">{thirdPartyTrust.highRiskProviders}</p>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Footprint</p>
            <p className="mt-2 text-2xl font-semibold text-slate-950">
              {thirdPartyTrust.totalProviders === 0 ? "Minimal" : thirdPartyTrust.totalProviders <= 5 ? "Moderate" : "Broad"}
            </p>
          </div>
        </div>

        {thirdPartyTrust.providers.length > 0 && (
          <div className="grid gap-3">
            {thirdPartyTrust.providers.map((provider) => (
              <div key={provider.domain} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-900">{provider.name}</span>
                  <Badge variant="outline">{categoryLabel[provider.category]}</Badge>
                  <Badge variant="secondary" className={riskStyles[provider.risk]}>
                    {provider.risk} risk
                  </Badge>
                </div>
                <p className="mt-2 text-sm text-slate-600">{provider.domain}</p>
                <p className="mt-1 text-xs text-slate-500">{provider.evidence}</p>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-2">
          {thirdPartyTrust.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {thirdPartyTrust.issues.map((issue) => (
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
