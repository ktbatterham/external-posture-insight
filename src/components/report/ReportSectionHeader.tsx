interface ReportSectionHeaderProps {
  eyebrow: string;
  title: string;
  description?: string;
}

export const sectionTitleClass = "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400";

export const ReportSectionHeader = ({
  eyebrow,
  title,
  description,
}: ReportSectionHeaderProps) => (
  <div className="max-w-3xl space-y-3">
    <p className={sectionTitleClass}>{eyebrow}</p>
    <div className="space-y-2">
      <h2 className="text-3xl font-semibold tracking-[-0.035em] text-white">{title}</h2>
      {description ? <p className="text-sm leading-7 text-slate-400">{description}</p> : null}
    </div>
  </div>
);
