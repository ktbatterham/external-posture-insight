import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SecurityHeaderResult } from "@/types/analysis";

interface HeadersTableProps {
  headers: SecurityHeaderResult[];
}

const statusStyles: Record<SecurityHeaderResult["status"], string> = {
  present: "bg-emerald-100 text-emerald-800 border-emerald-200",
  warning: "bg-amber-100 text-amber-900 border-amber-200",
  missing: "bg-rose-100 text-rose-800 border-rose-200",
};

const statusIcons = {
  present: <CheckCircle2 className="h-4 w-4" />,
  warning: <AlertTriangle className="h-4 w-4" />,
  missing: <ShieldAlert className="h-4 w-4" />,
};

export const HeadersTable = ({ headers }: HeadersTableProps) => {
  return (
    <div className="space-y-4">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[220px]">Header</TableHead>
            <TableHead className="w-[120px]">Status</TableHead>
            <TableHead>Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {headers.map((header) => (
            <TableRow key={header.key} className="align-top">
              <TableCell className="space-y-1">
                <div className="font-medium text-slate-950">{header.label}</div>
                <p className="text-xs text-slate-500">{header.description}</p>
              </TableCell>
              <TableCell>
                <Badge variant="outline" className={`gap-1 ${statusStyles[header.status]}`}>
                  {statusIcons[header.status]}
                  {header.status}
                </Badge>
              </TableCell>
              <TableCell className="space-y-2">
                <code className="block rounded-md bg-slate-100 px-3 py-2 text-xs text-slate-700">
                  {header.value ?? "Not returned by the origin"}
                </code>
                <p className="text-xs text-slate-500">{header.summary}</p>
                {header.status !== "present" && (
                  <div className="flex gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                    <Info className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{header.recommendation}</span>
                  </div>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};
