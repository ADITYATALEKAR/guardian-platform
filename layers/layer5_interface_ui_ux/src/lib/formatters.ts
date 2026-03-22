export function asObject(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

export function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export function asNumber(v: unknown): number {
  return Number.isFinite(Number(v)) ? Number(v) : 0;
}

export function severityBand(value: unknown): string {
  const num = asNumber(value);
  if (num > 1) {
    if (num >= 8) return "critical";
    if (num >= 6) return "high";
    if (num >= 4) return "medium";
    return "low";
  }
  if (num >= 0.8) return "critical";
  if (num >= 0.6) return "high";
  if (num >= 0.4) return "medium";
  return "low";
}

export function formatTimestamp(ms: unknown): string {
  const n = asNumber(ms);
  if (!n) return "-";
  return new Date(n).toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function formatRelativeTime(ms: unknown): string {
  const n = asNumber(ms);
  if (!n) return "-";
  const diff = Date.now() - n;
  if (diff < 0) return "just now";
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatDuration(ms: unknown): string {
  const totalMs = Math.max(0, asNumber(ms));
  const totalSeconds = Math.floor(totalMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  }
  return `${seconds}s`;
}

export function formatScore(value: unknown, decimals = 2): string {
  const n = asNumber(value);
  return n.toFixed(decimals);
}

export function formatHash(hash: unknown, length = 12): string {
  const s = asString(hash);
  if (!s) return "-";
  return s.length > length ? s.slice(0, length) + "..." : s;
}

export function downloadJson(filename: string, payload: unknown): void {
  const text = JSON.stringify(payload ?? {}, null, 2);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } finally {
    URL.revokeObjectURL(url);
  }
}

export function downloadCsv(filename: string, headers: string[], rows: string[][]): void {
  const escape = (s: string) => {
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  };
  const lines = [headers.map(escape).join(",")];
  for (const row of rows) {
    lines.push(row.map(escape).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } finally {
    URL.revokeObjectURL(url);
  }
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
  unknown: "var(--color-severity-unknown)",
};

export function severityColor(band: string): string {
  return SEVERITY_COLORS[band] ?? SEVERITY_COLORS.unknown;
}
