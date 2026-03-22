import { severityColor } from "../../lib/formatters";

interface SeverityBadgeProps {
  band: string;
  label?: string;
}

export function SeverityBadge({ band, label }: SeverityBadgeProps) {
  const color = severityColor(band);
  const text = label ?? band.toUpperCase();

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-caption)",
        letterSpacing: "0.08em",
        textTransform: "uppercase",
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          backgroundColor: color,
          flexShrink: 0,
        }}
      />
      <span style={{ color }}>{text}</span>
    </span>
  );
}
