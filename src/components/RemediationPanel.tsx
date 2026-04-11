import { useState } from "react";
import { Copy, Wrench } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock } from "@/components/ui/panel-primitives";
import { RemediationSnippet } from "@/types/analysis";

interface RemediationPanelProps {
  remediation: RemediationSnippet[];
}

const labels: Record<RemediationSnippet["platform"], string> = {
  nginx: "Nginx",
  apache: "Apache",
  cloudflare: "Cloudflare",
  vercel: "Vercel",
  netlify: "Netlify",
};

export const RemediationPanel = ({ remediation }: RemediationPanelProps) => {
  const [selected, setSelected] = useState<RemediationSnippet["platform"]>(remediation[0]?.platform ?? "nginx");

  if (!remediation.length) {
    return null;
  }

  const active = remediation.find((item) => item.platform === selected) ?? remediation[0];

  const copySnippet = async () => {
    await navigator.clipboard.writeText(active.snippet);
    toast.success(`${labels[active.platform]} snippet copied`);
  };

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wrench className="h-5 w-5" />
          Fix Snippets
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {remediation.map((item) => (
            <button
              key={item.platform}
              type="button"
              onClick={() => setSelected(item.platform)}
              className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                item.platform === active.platform
                  ? "bg-slate-900 text-white"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              {labels[item.platform]}
            </button>
          ))}
        </div>

        <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <h3 className="text-lg font-semibold text-slate-950">{active.title}</h3>
              <p className="mt-1 text-sm text-slate-600">{active.description}</p>
              <p className="mt-2 text-xs uppercase tracking-[0.18em] text-slate-500">{active.filename}</p>
            </div>
            <Button variant="outline" className="rounded-2xl" onClick={copySnippet}>
              <Copy className="mr-2 h-4 w-4" />
              Copy
            </Button>
          </div>

          <CodeBlock>{active.snippet}</CodeBlock>
        </div>
      </CardContent>
    </Card>
  );
};
