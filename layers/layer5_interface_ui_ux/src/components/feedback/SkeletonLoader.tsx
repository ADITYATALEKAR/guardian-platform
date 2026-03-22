interface SkeletonProps {
  variant?: "card" | "table" | "text" | "metric";
  count?: number;
}

function SkeletonBlock({ width, height }: { width: string; height: string }) {
  return (
    <div
      style={{
        width,
        height,
        background: "var(--dim)",
        borderRadius: 2,
        animation: "pulse 1.5s ease-in-out infinite",
      }}
    />
  );
}

function SkeletonMetricRow({ count }: { count: number }) {
  return (
    <div className="g-metric-grid">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="g-metric-card" style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <SkeletonBlock width="60%" height="10px" />
          <SkeletonBlock width="40%" height="28px" />
        </div>
      ))}
    </div>
  );
}

function SkeletonTableRows({ count }: { count: number }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          style={{
            display: "flex",
            gap: 16,
            padding: "10px 12px",
            background: "var(--panel)",
          }}
        >
          <SkeletonBlock width="20%" height="14px" />
          <SkeletonBlock width="15%" height="14px" />
          <SkeletonBlock width="10%" height="14px" />
          <SkeletonBlock width="12%" height="14px" />
          <SkeletonBlock width="8%" height="14px" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonLoader({ variant = "text", count = 1 }: SkeletonProps) {
  if (variant === "metric") return <SkeletonMetricRow count={count} />;
  if (variant === "table") return <SkeletonTableRows count={count} />;
  if (variant === "card") {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} style={{ background: "var(--panel)", border: "1px solid var(--border)", padding: 12 }}>
            <SkeletonBlock width="70%" height="12px" />
            <div style={{ marginTop: 8 }}>
              <SkeletonBlock width="40%" height="10px" />
            </div>
          </div>
        ))}
      </div>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonBlock key={i} width={i === 0 ? "80%" : "60%"} height="12px" />
      ))}
    </div>
  );
}
