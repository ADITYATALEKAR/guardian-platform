interface MetricCardProps {
  label: string;
  value: string | number;
  color?: string;
  onClick?: () => void;
}

export function MetricCard({ label, value, color, onClick }: MetricCardProps) {
  return (
    <div
      className="g-metric-card"
      onClick={onClick}
      style={{
        cursor: onClick ? "pointer" : undefined,
        transition: onClick ? "background-color 0.12s ease" : undefined,
      }}
      onMouseEnter={(e) => {
        if (onClick) (e.currentTarget as HTMLElement).style.background = "var(--surface)";
      }}
      onMouseLeave={(e) => {
        if (onClick) (e.currentTarget as HTMLElement).style.background = "var(--panel)";
      }}
    >
      <div className="g-metric-key">{label}</div>
      <div
        className="g-metric-value"
        style={{ color: color ?? "var(--pure)" }}
      >
        {value}
      </div>
    </div>
  );
}
