import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Cloud, Code2, Globe, Network, Server, Shield } from "lucide-react";
import { TechnologyResult } from "@/types/analysis";

interface TechnologyStackProps {
  technologies: TechnologyResult[];
}

const categoryConfig = {
  server: {
    icon: <Server className="h-4 w-4" />,
    color: "bg-sky-100 text-sky-900",
  },
  frontend: {
    icon: <Code2 className="h-4 w-4" />,
    color: "bg-emerald-100 text-emerald-900",
  },
  security: {
    icon: <Shield className="h-4 w-4" />,
    color: "bg-amber-100 text-amber-900",
  },
  hosting: {
    icon: <Cloud className="h-4 w-4" />,
    color: "bg-indigo-100 text-indigo-900",
  },
  network: {
    icon: <Network className="h-4 w-4" />,
    color: "bg-violet-100 text-violet-900",
  },
} as const;

const categoryOrder: Array<keyof typeof categoryConfig> = ["network", "hosting", "server", "frontend", "security"];

const confidenceStyles = {
  high: "bg-slate-200 text-slate-900",
  medium: "bg-amber-100 text-amber-900",
  low: "bg-sky-100 text-sky-900",
} as const;

export const TechnologyStack = ({ technologies }: TechnologyStackProps) => {
  if (!technologies.length) {
    return null;
  }

  const grouped = technologies.reduce<Record<string, TechnologyResult[]>>((acc, tech) => {
    acc[tech.category] = [...(acc[tech.category] || []), tech];
    return acc;
  }, {});

  return (
    <Card className="border-slate-200 shadow-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-900">
          <Globe className="h-5 w-5" />
          Detected Stack
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {categoryOrder.filter((category) => grouped[category]?.length).map((category) => {
          const items = grouped[category];
          const config = categoryConfig[category as keyof typeof categoryConfig];
          return (
            <div key={category} className="space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold capitalize text-slate-700">
                {config.icon}
                {category}
              </div>
              <div className="grid gap-3">
                {items.map((tech) => (
                  <div
                    key={`${tech.category}-${tech.name}-${tech.version ?? "none"}`}
                    className="rounded-2xl border border-slate-200 bg-white px-4 py-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium text-slate-900">{tech.name}</div>
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <Badge variant="secondary" className={config.color}>
                          {tech.version ?? tech.detection}
                        </Badge>
                        <Badge variant="secondary" className={confidenceStyles[tech.confidence]}>
                          {tech.confidence} confidence
                        </Badge>
                      </div>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">{tech.evidence}</p>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};
