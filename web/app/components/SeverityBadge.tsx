import type { Severity } from "@/lib/protocol";

const STYLES: Record<Severity, { bg: string; fg: string; label: string }> = {
  critical: { bg: "var(--color-sev-critical)", fg: "#1a0306", label: "CRITICAL" },
  high: { bg: "var(--color-sev-high)", fg: "#1f0d00", label: "HIGH" },
  medium: { bg: "var(--color-sev-medium)", fg: "#1c1600", label: "MEDIUM" },
  low: { bg: "var(--color-sev-low)", fg: "#021018", label: "LOW" },
  info: { bg: "var(--color-sev-info)", fg: "#0a1117", label: "INFO" },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = STYLES[severity] ?? STYLES.info;
  return (
    <span
      className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold tracking-widest"
      style={{ backgroundColor: s.bg, color: s.fg }}
    >
      {s.label}
    </span>
  );
}
