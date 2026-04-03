import { Cookie, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CookieResult } from "@/types/analysis";

interface CookieAnalysisProps {
  cookies: CookieResult[];
}

const riskStyles: Record<CookieResult["risk"], string> = {
  low: "bg-emerald-100 text-emerald-900",
  medium: "bg-amber-100 text-amber-900",
  high: "bg-rose-100 text-rose-900",
};

export const CookieAnalysis = ({ cookies }: CookieAnalysisProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-900">
          <Cookie className="h-5 w-5" />
          Cookie Security
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!cookies.length ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-6 text-sm text-slate-500">
            No `Set-Cookie` headers were returned on the scanned response.
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cookies.map((cookie) => (
                  <TableRow key={cookie.name} className="align-top">
                    <TableCell className="font-medium text-slate-900">{cookie.name}</TableCell>
                    <TableCell className="space-y-2">
                      <div className="flex flex-wrap gap-2">
                        <Badge variant={cookie.secure ? "default" : "destructive"}>
                          Secure {cookie.secure ? "on" : "off"}
                        </Badge>
                        <Badge variant={cookie.httpOnly ? "default" : "destructive"}>
                          HttpOnly {cookie.httpOnly ? "on" : "off"}
                        </Badge>
                        <Badge variant={cookie.sameSite ? "outline" : "destructive"}>
                          SameSite {cookie.sameSite ?? "missing"}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-slate-600">
                      <div>{cookie.domain ? `Domain ${cookie.domain}` : "Host-only"}</div>
                      <div>{cookie.path ? `Path ${cookie.path}` : "Default path"}</div>
                      <div>{cookie.expires ? `Expires ${cookie.expires}` : "Session cookie"}</div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className={riskStyles[cookie.risk]}>
                        {cookie.risk} risk
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            <div className="space-y-3">
              {cookies.flatMap((cookie) =>
                cookie.issues.map((issue) => (
                  <div
                    key={`${cookie.name}-${issue}`}
                    className="flex gap-3 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-900"
                  >
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      <span className="font-medium">{cookie.name}</span>: {issue}
                    </span>
                  </div>
                )),
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
