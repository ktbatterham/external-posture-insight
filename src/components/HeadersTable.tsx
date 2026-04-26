import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SecurityHeaderResult } from "@/types/analysis";

interface HeadersTableProps {
  headers: SecurityHeaderResult[];
}

const statusStyles: Record<SecurityHeaderResult["status"], string> = {
  present: "border-white/10 bg-white/[0.08] text-slate-100",
  warning: "border-[#b56a2c]/35 bg-[#b56a2c]/14 text-[#f0d5bc]",
  missing: "border-[#8e5c3b]/35 bg-[#8e5c3b]/14 text-[#f0d5bc]",
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
          <TableRow className="border-white/10 hover:bg-transparent">
            <TableHead className="w-[220px] text-slate-400">Header</TableHead>
            <TableHead className="w-[120px] text-slate-400">Status</TableHead>
            <TableHead className="text-slate-400">Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {headers.map((header) => (
            <TableRow key={header.key} className="align-top border-white/10 hover:bg-white/[0.02]">
              <TableCell className="space-y-1">
                <div className="font-medium text-slate-100">{header.label}</div>
                <p className="text-xs text-slate-400">{header.description}</p>
              </TableCell>
              <TableCell>
                <Badge variant="outline" className={`gap-1 ${statusStyles[header.status]}`}>
                  {statusIcons[header.status]}
                  {header.status}
                </Badge>
              </TableCell>
              <TableCell className="space-y-2">
                <code className="block rounded-xl border border-white/10 bg-slate-950/75 px-3 py-2 text-xs text-slate-200">
                  {header.value ?? "Not returned by the origin"}
                </code>
                <p className="text-xs text-slate-400">{header.summary}</p>
                {header.status !== "present" && (
                  <div className="flex gap-2 rounded-xl border border-[#b56a2c]/35 bg-[#b56a2c]/12 px-3 py-2 text-xs text-[#f0d5bc]">
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
