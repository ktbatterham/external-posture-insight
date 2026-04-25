import { Cloud, Info, Network } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, SignalList, StatBox } from "@/components/ui/panel-primitives";
import { InfrastructureInfo } from "@/types/analysis";

interface InfrastructurePanelProps {
  infrastructure: InfrastructureInfo;
}

const sourceLabel = {
  dns: "DNS",
  reverse_dns: "Reverse DNS",
  headers: "Headers",
  technology: "Stack",
} as const;

const categoryClass = {
  cloud: "bg-sky-100 text-sky-900",
  cdn: "bg-violet-100 text-violet-900",
  edge: "bg-emerald-100 text-emerald-900",
  paas: "bg-indigo-100 text-indigo-900",
  hosting: "bg-amber-100 text-amber-900",
} as const;

export const InfrastructurePanel = ({ infrastructure }: InfrastructurePanelProps) => (
  <Card className="border-slate-200 bg-white shadow-sm">
    <CardHeader>
      <CardTitle className="flex items-center gap-2 text-slate-950">
        <Network className="h-5 w-5" />
        Infrastructure Read
      </CardTitle>
      <p className="text-sm text-slate-500">
        Passive hosting and edge-provider inference from DNS, reverse DNS, headers, and detected stack signals.
      </p>
    </CardHeader>
    <CardContent className="space-y-5">
      <div className="grid gap-3 md:grid-cols-3">
        <StatBox label="Providers" value={<p className="text-3xl font-bold">{infrastructure.providers.length}</p>} />
        <StatBox label="Addresses" value={<p className="text-3xl font-bold">{infrastructure.addresses.length}</p>} />
        <StatBox label="CNAMEs" value={<p className="text-3xl font-bold">{infrastructure.cnameTargets.length}</p>} />
      </div>

      {infrastructure.providers.length ? (
        <div className="grid gap-3">
          {infrastructure.providers.map((signal, index) => (
            <div
              key={`${signal.provider}-${signal.source}-${index}`}
              className="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 font-semibold text-slate-950">
                  <Cloud className="h-4 w-4 text-slate-500" />
                  {signal.provider}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary" className={categoryClass[signal.category]}>
                    {signal.category}
                  </Badge>
                  <Badge variant="secondary" className="bg-slate-200 text-slate-900">
                    {sourceLabel[signal.source]}
                  </Badge>
                </div>
              </div>
              <p className="mt-2 break-words text-sm text-slate-600">{signal.evidence}</p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState>No obvious cloud, CDN, edge, or hosting provider was inferred from passive evidence.</EmptyState>
      )}

      <SignalList
        title="Infrastructure read"
        items={[infrastructure.summary]}
        icon={<Info />}
        variant={infrastructure.providers.length ? "success" : "neutral"}
      />
    </CardContent>
  </Card>
);
