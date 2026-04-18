import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// StatBox
// A labelled metric/info cell used in grid layouts throughout the app.
// ---------------------------------------------------------------------------

type StatBoxVariant = "default" | "critical" | "warning" | "info";

const statBoxVariants: Record<StatBoxVariant, { container: string; label: string; value: string }> = {
  default: {
    container: "border-slate-200/90 bg-white/90",
    label: "text-slate-500",
    value: "text-slate-950",
  },
  critical: {
    container: "border-rose-200/90 bg-white/90",
    label: "text-rose-700",
    value: "text-rose-900",
  },
  warning: {
    container: "border-amber-200/90 bg-white/90",
    label: "text-amber-700",
    value: "text-amber-900",
  },
  info: {
    container: "border-sky-200/90 bg-white/90",
    label: "text-sky-700",
    value: "text-sky-900",
  },
};

interface StatBoxProps {
  label: string;
  value: React.ReactNode;
  note?: React.ReactNode;
  variant?: StatBoxVariant;
  className?: string;
}

export const StatBox = ({ label, value, note, variant = "default", className }: StatBoxProps) => {
  const v = statBoxVariants[variant];
  return (
    <div
      className={cn(
        "rounded-2xl border p-4 shadow-[0_8px_18px_-14px_rgba(15,23,42,0.3),0_1px_0_rgba(255,255,255,0.65)_inset]",
        v.container,
        className,
      )}
    >
      <p className={cn("text-xs uppercase tracking-[0.18em]", v.label)}>{label}</p>
      <div className={cn("mt-2", v.value)}>{value}</div>
      {note && <div className="mt-1">{note}</div>}
    </div>
  );
};

// ---------------------------------------------------------------------------
// StatusAlert
// A coloured alert row with an optional icon — used for strengths and issues.
// ---------------------------------------------------------------------------

type StatusAlertVariant = "success" | "warning" | "critical" | "info";

const statusAlertVariants: Record<StatusAlertVariant, string> = {
  success: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  critical: "border-rose-200 bg-rose-50 text-rose-900",
  info: "border-sky-200 bg-sky-50 text-sky-900",
};

interface StatusAlertProps {
  variant: StatusAlertVariant;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export const StatusAlert = ({ variant, icon, children, className }: StatusAlertProps) => (
  <div
    className={cn(
      "rounded-2xl border px-4 py-3 text-sm",
      icon ? "flex gap-3" : "",
      statusAlertVariants[variant],
      className,
    )}
  >
    {icon && <div className="mt-0.5 shrink-0 [&>svg]:h-4 [&>svg]:w-4">{icon}</div>}
    <div className="min-w-0">{children}</div>
  </div>
);

// ---------------------------------------------------------------------------
// EmptyState
// Dashed-border placeholder for sections with no data.
// ---------------------------------------------------------------------------

interface EmptyStateProps {
  children: React.ReactNode;
  className?: string;
}

export const EmptyState = ({ children, className }: EmptyStateProps) => (
  <div
    className={cn(
      "rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-6 text-sm text-slate-500",
      className,
    )}
  >
    {children}
  </div>
);

// ---------------------------------------------------------------------------
// CodeBlock
// Dark pre/code block for snippets and raw config output.
// ---------------------------------------------------------------------------

interface CodeBlockProps {
  children: React.ReactNode;
  className?: string;
}

export const CodeBlock = ({ children, className }: CodeBlockProps) => (
  <pre className={cn("overflow-x-auto rounded-2xl bg-slate-950 p-4 text-xs text-slate-100", className)}>
    <code>{children}</code>
  </pre>
);
