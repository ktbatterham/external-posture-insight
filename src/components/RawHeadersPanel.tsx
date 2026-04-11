import { FileJson } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock } from "@/components/ui/panel-primitives";

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
        <CodeBlock className="whitespace-pre-wrap break-all">
          {JSON.stringify(headers, null, 2)}
        </CodeBlock>
      </CardContent>
    </Card>
  );
};
