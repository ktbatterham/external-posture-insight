import { FileSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Contact</p>
            <div className="mt-2 space-y-1 text-sm text-slate-700">
              {securityTxt.contact.length ? securityTxt.contact.map((item) => <p key={item}>{item}</p>) : <p>Not listed</p>}
            </div>
          </div>
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Expires</p>
            <p className="mt-2 text-sm text-slate-700">{securityTxt.expires ?? "Not listed"}</p>
          </div>
        </div>

        {securityTxt.policy.length > 0 && (
          <div className="rounded-2xl bg-slate-50 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Policy</p>
            <div className="mt-2 space-y-1 text-sm text-slate-700">
              {securityTxt.policy.map((item) => <p key={item}>{item}</p>)}
            </div>
          </div>
        )}

        <div className="space-y-2">
          {securityTxt.issues.map((issue) => (
            <div
              key={issue}
              className={`flex gap-3 rounded-2xl px-4 py-3 text-sm ${
                securityTxt.status === "present"
                  ? "border border-amber-200 bg-amber-50 text-amber-900"
                  : "border border-rose-200 bg-rose-50 text-rose-900"
              }`}
            >
              {securityTxt.status === "present" ? (
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              ) : (
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              )}
              <span>{issue}</span>
            </div>
          ))}

          {securityTxt.status === "present" && securityTxt.issues.length === 0 && (
            <div className="flex gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Valid security.txt discovered with contact information.</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
