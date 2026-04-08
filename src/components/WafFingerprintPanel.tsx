import { WafFingerprintInfo } from "@/types/analysis";

interface WafFingerprintPanelProps {
  wafFingerprint: WafFingerprintInfo;
}

export const WafFingerprintPanel = ({ wafFingerprint }: WafFingerprintPanelProps) => {
  const strengthItems = wafFingerprint.strengths.length
    ? wafFingerprint.strengths
    : ["No positive WAF or edge-protection evidence was confirmed from passive signals."];
  const reviewItems = wafFingerprint.issues.length
    ? wafFingerprint.issues
    : wafFingerprint.detected
      ? ["No WAF-specific review issues were identified from the passive evidence collected."]
      : ["Passive evidence was limited, so absence of a branded match does not prove no WAF or edge control is present."];

  return (
  <section className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-sm">
    <div className="flex items-center justify-between gap-3">
      <div>
        <h2 className="text-2xl font-bold text-slate-950">WAF & Edge Fingerprint</h2>
        <p className="mt-1 text-sm text-slate-500">
          Passive edge and protection-provider inference from response headers, block-page markers, and redirect behavior.
        </p>
      </div>
      <div className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-slate-700">
        {wafFingerprint.detected ? "Detected" : "No strong match"}
      </div>
    </div>

    <p className="mt-4 text-sm leading-6 text-slate-600">{wafFingerprint.summary}</p>

    <div className="mt-6 grid gap-6 xl:grid-cols-2">
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Providers</h3>
        {wafFingerprint.providers.length ? (
          <ul className="mt-3 space-y-3 text-sm text-slate-700">
            {wafFingerprint.providers.map((provider) => (
              <li key={`${provider.name}-${provider.evidence}`} className="rounded-2xl border border-slate-200 bg-white p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="font-semibold text-slate-900">{provider.name}</span>
                  <span className="text-xs uppercase tracking-[0.12em] text-slate-500">
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

      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
        <h3 className="text-sm font-semibold uppercase tracking-[0.12em] text-slate-500">Edge evidence</h3>
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
