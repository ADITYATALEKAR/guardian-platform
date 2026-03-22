interface EmptyStateProps {
  message: string;
  action?: string;
  onAction?: () => void;
}

export function EmptyState({ message, action, onAction }: EmptyStateProps) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "64px 24px",
        gap: 16,
      }}
    >
      <div
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "var(--font-size-secondary)",
          color: "var(--muted)",
          letterSpacing: "0.06em",
          textAlign: "center",
          maxWidth: 400,
        }}
      >
        {message}
      </div>
      {action && onAction && (
        <button className="btn btn-neutral" onClick={onAction}>
          {action}
        </button>
      )}
    </div>
  );
}
