export function formatOwnershipLabel(
  value: string,
  variant: "long" | "short" = "long",
): string {
  const token = String(value || "").trim().toLowerCase();
  if (variant === "short") {
    switch (token) {
      case "first_party":
        return "FIRST";
      case "adjacent_dependency":
        return "ADJ";
      case "third_party_dependency":
        return "3P";
      default:
        return "UNK";
    }
  }

  switch (token) {
    case "first_party":
      return "First Party";
    case "adjacent_dependency":
      return "Adjacent Dependency";
    case "third_party_dependency":
      return "Third-Party Dependency";
    default:
      return "Unknown";
  }
}

export function summarizeDiscoverySources(
  sources: string[],
  fallback?: string,
  limit: number = 3,
): string {
  const normalized = Array.isArray(sources)
    ? sources.map((item) => String(item || "").trim()).filter(Boolean)
    : [];
  if (normalized.length === 0) {
    return String(fallback || "").trim() || "-";
  }
  const visible = normalized.slice(0, Math.max(1, limit));
  const hidden = normalized.length - visible.length;
  return hidden > 0 ? `${visible.join(", ")} +${hidden}` : visible.join(", ");
}

export function isTenantRelevantEndpoint(
  endpoint:
    | {
        ownership_category?: string | null;
        relevance_score?: number | null;
      }
    | null
    | undefined,
): boolean {
  if (!endpoint) return true;
  const ownership = String(endpoint.ownership_category || "").trim().toLowerCase();
  if (ownership === "first_party" || ownership === "adjacent_dependency") {
    return true;
  }
  return Number(endpoint.relevance_score ?? 0) >= 0.55;
}
