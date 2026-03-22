import { formatTimestamp, formatHash } from "../../lib/formatters";

interface ProvenanceBarProps {
  cycleId?: string;
  snapshotHash?: string;
  firstSeenMs?: number;
  lastSeenMs?: number;
  timestamp?: number;
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-label)",
          letterSpacing: "0.15em",
          textTransform: "uppercase",
          color: "var(--muted)",
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-caption)",
          color: "var(--ghost)",
        }}
      >
        {value}
      </span>
    </span>
  );
}

export function ProvenanceBar({
  cycleId: _cycleId,
  snapshotHash: _snapshotHash,
  firstSeenMs,
  lastSeenMs,
  timestamp,
}: ProvenanceBarProps) {
  // Internal IDs (cycle_id, hash) are kept as props for compatibility but not displayed to users
  const hasAnyTimestamp = firstSeenMs || lastSeenMs || timestamp;
  if (!hasAnyTimestamp) return null;

  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 16,
        padding: "8px 0",
        borderTop: "1px solid var(--border)",
      }}
    >
      {firstSeenMs ? <KV label="First Seen" value={formatTimestamp(firstSeenMs)} /> : null}
      {lastSeenMs ? <KV label="Last Seen" value={formatTimestamp(lastSeenMs)} /> : null}
      {timestamp ? <KV label="Observed" value={formatTimestamp(timestamp)} /> : null}
    </div>
  );
}
