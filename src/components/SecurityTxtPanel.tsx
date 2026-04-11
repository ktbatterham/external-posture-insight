import { FileSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { SecurityTxtInfo } from "@/types/analysis";

interface SecurityTxtPanelProps {
  securityTxt: SecurityTxtInfo;
}

const statusStyles: Record<SecurityTxtInfo["status"], string> = {
  present: "bg-emerald-100 text-emerald-900",
  invalid: "bg-amber-100 text-amber-900",
  missing: "bg-rose-100 text-rose-900",
};

export const SecurityTxtPanel = ({ securityTxt }: SecurityTxtPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="h-5 w-5" />
          security.txt
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3">
          <Badge variant="secondary" className={statusStyles[securityTxt.status]}>
            {securityTxt.status}
          </Badge>
          {securityTxt.url ? (
            <a href={securityTxt.url} target="_blank" rel="noreferrer" className="text-sm text-sky-700 underline">
              {securityTxt.url}
            </a>
          ) : (
            <span className="text-sm text-slate-500">No file discovered</span>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="Contact"
            value={
              <div className="space-y-1 text-sm text-slate-700">
                {securityTxt.contact.length ? securityTxt.contact.map((item) => <p key={item}>{item}</p>) : <p>Not listed</p>}
              </div>
            }
          />
          <StatBox
            label="Expires"
            value={<p className="text-sm text-slate-700">{securityTxt.expires ?? "Not listed"}</p>}
          />
        </div>

        {securityTxt.policy.length > 0 && (
          <StatBox
            label="Policy"
            value={
              <div className="space-y-1 text-sm text-slate-700">
                {securityTxt.policy.map((item) => <p key={item}>{item}</p>)}
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {securityTxt.issues.map((issue) => (
            <StatusAlert
              key={issue}
              variant={securityTxt.status === "present" ? "warning" : "critical"}
              icon={<ShieldAlert />}
            >
              {issue}
            </StatusAlert>
          ))}
          {securityTxt.status === "present" && securityTxt.issues.length === 0 && (
            <StatusAlert variant="success" icon={<ShieldCheck />}>
              Valid security.txt discovered with contact information.
            </StatusAlert>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
