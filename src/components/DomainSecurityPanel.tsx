import { Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DomainSecurityInfo } from "@/types/analysis";

interface DomainSecurityPanelProps {
  domainSecurity: DomainSecurityInfo;
}

export const DomainSecurityPanel = ({ domainSecurity }: DomainSecurityPanelProps) => {
  return (
    <Card className="h-full border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Mail className="h-5 w-5" />
          Domain & Email Security
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">SPF</p>
            <p className="mt-2 overflow-hidden break-words text-sm leading-6 text-slate-700">{domainSecurity.spf ?? "Not found"}</p>
          </div>
          <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">DMARC</p>
            <p className="mt-2 overflow-hidden break-words text-sm leading-6 text-slate-700">{domainSecurity.dmarc ?? "Not found"}</p>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">MX records</p>
            <div className="mt-2 space-y-2 text-sm leading-6 text-slate-700">
              {domainSecurity.mxRecords.length ? domainSecurity.mxRecords.map((record) => <p key={record} className="overflow-hidden break-words">{record}</p>) : <p>None</p>}
            </div>
          </div>
          <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">CAA records</p>
            <div className="mt-2 space-y-2 text-sm leading-6 text-slate-700">
              {domainSecurity.caaRecords.length ? domainSecurity.caaRecords.map((record) => <p key={record} className="overflow-hidden break-words">{record}</p>) : <p>None</p>}
            </div>
          </div>
        </div>

        <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">DNSSEC</p>
          <div className="mt-2 space-y-2 text-sm leading-6 text-slate-700">
            <p>Status: {domainSecurity.dnssec.status === "signed" ? "Signed" : domainSecurity.dnssec.status === "not_signed" ? "Not signed" : "Unknown"}</p>
            {domainSecurity.dnssec.dsRecords.length ? (
              domainSecurity.dnssec.dsRecords.map((record) => (
                <p key={record} className="overflow-hidden break-words">{record}</p>
              ))
            ) : (
              <p>No DS records detected.</p>
            )}
          </div>
        </div>

        <div className="min-w-0 rounded-2xl bg-slate-50 p-4">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">MTA-STS</p>
          <div className="mt-2 space-y-2 text-sm leading-6 text-slate-700">
            <p className="overflow-hidden break-words">DNS: {domainSecurity.mtaSts.dns ?? "Not found"}</p>
            {domainSecurity.mtaSts.policyUrl && <p className="overflow-hidden break-words">Policy URL: {domainSecurity.mtaSts.policyUrl}</p>}
            {domainSecurity.mtaSts.policy && (
              <pre className="overflow-x-auto rounded-xl bg-slate-950 p-3 text-xs text-slate-100">
                <code>{domainSecurity.mtaSts.policy}</code>
              </pre>
            )}
          </div>
        </div>

        <div className="flex min-w-0 flex-wrap gap-2">
          {domainSecurity.nsRecords.slice(0, 6).map((record) => (
            <Badge key={record} variant="outline" className="max-w-full overflow-hidden break-all text-left">
              {record}
            </Badge>
          ))}
        </div>

        <div className="space-y-2">
          {domainSecurity.strengths.map((strength) => (
            <div key={strength} className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{strength}</span>
            </div>
          ))}
          {domainSecurity.issues.map((issue) => (
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
