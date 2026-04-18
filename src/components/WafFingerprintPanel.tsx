import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { WafFingerprintInfo } from "@/types/analysis";

interface WafFingerprintPanelProps {
  wafFingerprint: WafFingerprintInfo;
}

export const WafFingerprintPanel = ({ wafFingerprint }: WafFingerprintPanelProps) => {
  const reviewItems = wafFingerprint.issues;
  const strengthItems = [
    ...(wafFingerprint.strengths.length
    ? wafFingerprint.strengths
    : ["No positive WAF or edge-protection evidence was confirmed from passive signals."]),
    ...(reviewItems.length === 0 && wafFingerprint.detected
      ? ["No WAF-specific review issues were identified from the passive evidence collected."]
      : []),
    ...(reviewItems.length === 0 && !wafFingerprint.detected
      ? ["Passive evidence was limited, so absence of a branded match does not prove no WAF or edge control is present."]
      : []),
  ];

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>WAF & Edge Fingerprint</CardTitle>
          <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-slate-700">
            {wafFingerprint.detected ? "Detected" : "No strong match"}
          </div>
        </div>
        <p className="text-sm text-slate-500">
          Passive edge and protection-provider inference from response headers, block-page markers, and redirect behavior.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm leading-6 text-slate-600">{wafFingerprint.summary}</p>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Providers</p>
            {wafFingerprint.providers.length ? (
              <ul className="mt-3 space-y-3 text-sm text-slate-700">
                {wafFingerprint.providers.map((provider) => (
                  <li key={`${provider.name}-${provider.evidence}`} className="rounded-2xl border border-slate-200 bg-white p-3">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-semibold text-slate-900">{provider.name}</span>
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">
                        {provider.detection} · {provider.confidence}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">{provider.evidence}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No branded WAF or edge-protection provider was conclusively identified.</p>
            )}
          </div>

          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Edge evidence</p>
            {wafFingerprint.edgeSignals.length ? (
              <ul className="mt-3 space-y-2 text-sm text-slate-700">
                {wafFingerprint.edgeSignals.map((signal) => (
                  <li key={signal}>{signal}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-600">No additional edge-network clues were recorded.</p>
            )}
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
