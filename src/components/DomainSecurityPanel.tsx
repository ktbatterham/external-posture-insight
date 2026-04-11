import { Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock, StatBox, StatusAlert } from "@/components/ui/panel-primitives";
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
          <StatBox label="SPF" value={<p className="overflow-hidden break-words text-sm leading-6 text-slate-700">{domainSecurity.spf ?? "Not found"}</p>} />
          <StatBox label="DMARC" value={<p className="overflow-hidden break-words text-sm leading-6 text-slate-700">{domainSecurity.dmarc ?? "Not found"}</p>} />
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
