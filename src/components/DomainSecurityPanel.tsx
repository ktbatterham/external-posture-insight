import { Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock, StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { DomainSecurityInfo } from "@/types/analysis";

interface DomainSecurityPanelProps {
  domainSecurity: DomainSecurityInfo;
}

const policyBadgeClass = {
  strong: "border-emerald-200 bg-emerald-50 text-emerald-800",
  watch: "border-amber-200 bg-amber-50 text-amber-800",
  weak: "border-rose-200 bg-rose-50 text-rose-800",
  missing: "border-slate-200 bg-slate-100 text-slate-700",
} as const;

const policyLabel = {
  strong: "Strong",
  watch: "Watch",
  weak: "Weak",
  missing: "Missing",
} as const;

export const DomainSecurityPanel = ({ domainSecurity }: DomainSecurityPanelProps) => {
  const emailPolicy = domainSecurity.emailPolicy ?? {
    spf: {
      status: domainSecurity.spf ? "watch" : "missing",
      summary: domainSecurity.spf ? "SPF is present, but this older snapshot does not include parsed policy detail." : "No SPF record was detected at the zone apex.",
    },
    dmarc: {
      status: domainSecurity.dmarc ? "watch" : "missing",
      summary: domainSecurity.dmarc ? "DMARC is present, but this older snapshot does not include parsed policy detail." : "No DMARC record was detected.",
    },
  } as const;

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
          <StatBox
            label="SPF"
            value={
              <div className="space-y-3 text-sm leading-6 text-slate-700">
                <Badge variant="outline" className={policyBadgeClass[emailPolicy.spf.status]}>
                  {policyLabel[emailPolicy.spf.status]}
                </Badge>
                <p>{emailPolicy.spf.summary}</p>
                <p className="overflow-hidden break-words text-xs text-slate-500">{domainSecurity.spf ?? "Not found"}</p>
              </div>
            }
          />
          <StatBox
            label="DMARC"
            value={
              <div className="space-y-3 text-sm leading-6 text-slate-700">
                <Badge variant="outline" className={policyBadgeClass[emailPolicy.dmarc.status]}>
                  {policyLabel[emailPolicy.dmarc.status]}
                </Badge>
                <p>{emailPolicy.dmarc.summary}</p>
                <p className="overflow-hidden break-words text-xs text-slate-500">{domainSecurity.dmarc ?? "Not found"}</p>
              </div>
            }
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="MX records"
            value={
              <div className="space-y-2 text-sm leading-6 text-slate-700">
                {domainSecurity.mxRecords.length ? domainSecurity.mxRecords.map((record) => <p key={record} className="overflow-hidden break-words">{record}</p>) : <p>None</p>}
              </div>
            }
          />
          <StatBox
            label="CAA records"
            value={
              <div className="space-y-2 text-sm leading-6 text-slate-700">
                {domainSecurity.caaRecords.length ? domainSecurity.caaRecords.map((record) => <p key={record} className="overflow-hidden break-words">{record}</p>) : <p>None</p>}
              </div>
            }
          />
        </div>

        <StatBox
          label="DNSSEC"
          value={
            <div className="space-y-2 text-sm leading-6 text-slate-700">
              <p>Status: {domainSecurity.dnssec.status === "signed" ? "Signed" : domainSecurity.dnssec.status === "not_signed" ? "Not signed" : "Unknown"}</p>
              {domainSecurity.dnssec.dsRecords.length ? (
                domainSecurity.dnssec.dsRecords.map((record) => (
                  <p key={record} className="overflow-hidden break-words">{record}</p>
                ))
              ) : (
                <p>No DS records detected.</p>
              )}
            </div>
          }
        />

        <StatBox
          label="MTA-STS"
          value={
            <div className="space-y-2 text-sm leading-6 text-slate-700">
              <p className="overflow-hidden break-words">DNS: {domainSecurity.mtaSts.dns ?? "Not found"}</p>
              {domainSecurity.mtaSts.policyUrl && <p className="overflow-hidden break-words">Policy URL: {domainSecurity.mtaSts.policyUrl}</p>}
              {domainSecurity.mtaSts.policy && (
                <CodeBlock>{domainSecurity.mtaSts.policy}</CodeBlock>
              )}
            </div>
          }
        />

        <div className="flex min-w-0 flex-wrap gap-2">
          {domainSecurity.nsRecords.slice(0, 6).map((record) => (
            <Badge key={record} variant="outline" className="max-w-full overflow-hidden break-all text-left">
              {record}
            </Badge>
          ))}
        </div>

        <div className="space-y-2">
          {domainSecurity.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {domainSecurity.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
