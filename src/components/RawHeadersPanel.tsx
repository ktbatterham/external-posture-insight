import { FileJson } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface RawHeadersPanelProps {
  headers: Record<string, string>;
}

export const RawHeadersPanel = ({ headers }: RawHeadersPanelProps) => {
  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileJson className="h-5 w-5" />
          Raw Response Headers
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="rounded-2xl bg-slate-950 p-4 text-xs text-slate-100">
          <pre className="overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(headers, null, 2)}
          </pre>
        </div>
      </CardContent>
    </Card>
  );
};
