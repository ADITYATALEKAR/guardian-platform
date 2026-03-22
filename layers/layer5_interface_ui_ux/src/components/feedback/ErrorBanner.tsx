interface ErrorBannerProps {
  message: string;
  onRetry?: () => void;
  onDismiss?: () => void;
}

export function ErrorBanner({ message, onRetry, onDismiss }: ErrorBannerProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 14px",
        background: "rgba(218, 54, 51, 0.08)",
        border: "1px solid rgba(218, 54, 51, 0.25)",
        borderRadius: 2,
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-caption)",
        color: "var(--color-severity-critical)",
        marginBottom: 12,
      }}
    >
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry && (
        <button
          className="btn btn-small btn-neutral"
          onClick={onRetry}
          style={{ flexShrink: 0 }}
        >
          Retry
        </button>
      )}
      {onDismiss && (
        <button
          onClick={onDismiss}
          style={{
            background: "none",
            border: "none",
            color: "var(--muted)",
            cursor: "pointer",
            padding: 4,
            fontSize: 14,
          }}
        >
          x
        </button>
      )}
    </div>
  );
}
