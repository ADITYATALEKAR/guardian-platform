import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { dataSource } from "../lib/api";
import { useSessionStore } from "../stores/useSessionStore";
import {
  parseEndpointDTO,
  useDashboardStore,
  type EndpointDTO,
} from "../stores/useDashboardStore";
import { SeverityBadge } from "../components/display/SeverityBadge";
import { EmptyState } from "../components/feedback/EmptyState";
import { SkeletonLoader } from "../components/feedback/SkeletonLoader";
import { ErrorBanner } from "../components/feedback/ErrorBanner";
import {
  severityBand,
  severityColor,
  formatScore,
  formatRelativeTime,
  downloadCsv,
} from "../lib/formatters";
import { formatOwnershipLabel } from "../lib/endpointContext";
import { endpointDetailPath } from "../lib/routes";

const COLUMNS = [
  { key: "entity_id", label: "Endpoint", width: "2fr" },
  { key: "hostname", label: "Hostname", width: "1fr" },
  { key: "port", label: "Port", width: "60px" },
  { key: "observation_status", label: "State", width: "130px" },
  { key: "ownership_category", label: "Owner", width: "110px" },
  { key: "relevance_score", label: "Rel", width: "70px" },
  { key: "guardian_risk", label: "Risk", width: "70px" },
  { key: "confidence", label: "Conf", width: "70px" },
  { key: "alert_count", label: "Alerts", width: "60px" },
  { key: "tls_version", label: "TLS", width: "70px" },
  { key: "last_seen_ms", label: "Last Seen", width: "90px" },
] as const;

const PAGE_SIZE = 50;

type SortKey = (typeof COLUMNS)[number]["key"];

export function EndpointsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const tenantId = useSessionStore((s) => s.activeTenantId);
  const { data, loading, error, fetchDashboard } = useDashboardStore();
  const [endpointRows, setEndpointRows] = useState<EndpointDTO[]>([]);
  const [endpointRowsLoading, setEndpointRowsLoading] = useState(false);
  const [endpointRowsError, setEndpointRowsError] = useState<string | null>(null);
  const [endpointRowsTruncated, setEndpointRowsTruncated] = useState(false);

  const [sortKey, setSortKey] = useState<SortKey>("relevance_score");
  const [sortAsc, setSortAsc] = useState(false);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string | null>(
    searchParams.get("severity")
  );
  const [surfaceFilter, setSurfaceFilter] = useState<string>("all_related");

  useEffect(() => {
    if (tenantId && !data) fetchDashboard(tenantId);
  }, [tenantId, data, fetchDashboard]);

  useEffect(() => {
    if (!tenantId || !data?.cycle_id || data.health_summary.total_endpoints === 0) {
      setEndpointRows([]);
      setEndpointRowsTruncated(false);
      setEndpointRowsError(null);
      return;
    }
    let cancelled = false;
    setEndpointRowsLoading(true);
    setEndpointRowsError(null);
    dataSource
      .getAllEndpointPages(tenantId, { pageSize: 1000, maxPages: 20 })
      .then((payload) => {
        if (cancelled) return;
        const rows = Array.isArray(payload.rows) ? payload.rows.map(parseEndpointDTO) : [];
        setEndpointRows(rows);
        setEndpointRowsTruncated(Boolean(payload.truncated));
      })
      .catch((err) => {
        if (cancelled) return;
        setEndpointRowsError(String(err));
      })
      .finally(() => {
        if (!cancelled) setEndpointRowsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tenantId, data?.cycle_id, data?.health_summary.total_endpoints]);

  const filtered = useMemo(() => {
    let list = endpointRows;
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (ep) =>
          ep.entity_id.toLowerCase().includes(q) ||
          ep.hostname.toLowerCase().includes(q) ||
          ep.ip.toLowerCase().includes(q)
      );
    }
    if (severityFilter) {
      list = list.filter((ep) => severityBand(ep.guardian_risk) === severityFilter);
    }
    if (surfaceFilter === "observed_successful") {
      list = list.filter((ep) => ep.observation_status === "observed_successful");
    } else if (surfaceFilter === "observation_failed") {
      list = list.filter((ep) => ep.observation_status === "observation_failed");
    } else if (surfaceFilter === "not_yet_observed") {
      list = list.filter((ep) => ep.observation_status === "not_yet_observed");
    } else if (surfaceFilter === "third_party_linked") {
      list = list.filter((ep) => ep.ownership_category === "third_party_dependency");
    } else if (surfaceFilter === "historical_or_ct_only") {
      list = list.filter((ep) => ep.surface_tags.includes("historical_or_ct_only"));
    }
    return list;
  }, [endpointRows, search, severityFilter, surfaceFilter]);

  const sorted = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      const av = a[sortKey] as number | string;
      const bv = b[sortKey] as number | string;
      if (typeof av === "number" && typeof bv === "number") {
        return sortAsc ? av - bv : bv - av;
      }
      return sortAsc
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });
    return copy;
  }, [filtered, sortKey, sortAsc]);

  const paged = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(sorted.length / PAGE_SIZE);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(false);
    }
    setPage(0);
  };

  const handleExport = () => {
    const headers = COLUMNS.map((c) => c.label);
    const rows = sorted.map((ep) =>
      COLUMNS.map((c) => {
        const v = ep[c.key];
        if (c.key === "guardian_risk" || c.key === "confidence" || c.key === "relevance_score") return formatScore(v);
        if (c.key === "last_seen_ms") return String(v);
        return String(v);
      })
    );
    downloadCsv("guardian_endpoints.csv", headers, rows);
  };

  if ((loading && !data) || (endpointRowsLoading && endpointRows.length === 0 && data)) {
    return <SkeletonLoader variant="table" count={10} />;
  }
  if (error) return <ErrorBanner message={error} onRetry={() => tenantId && fetchDashboard(tenantId)} />;
  if (endpointRowsError && endpointRows.length === 0) {
    return <ErrorBanner message={endpointRowsError} onRetry={() => tenantId && fetchDashboard(tenantId)} />;
  }
  if (!data) return <EmptyState message="No scan data. Run a scan to discover endpoints." action="Start Onboarding" onAction={() => navigate("/onboarding")} />;
  if (data.health_summary.total_endpoints === 0) {
    return <EmptyState message="No scan data. Run a scan to discover endpoints." action="Start Onboarding" onAction={() => navigate("/onboarding")} />;
  }

  const gridCols = COLUMNS.map((c) => c.width).join(" ");

  return (
    <div className="g-scroll-page">
      <div className="g-scroll-page__header">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <input
          type="text"
          placeholder="Search endpoints..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          style={{
            flex: 1,
            maxWidth: 320,
            height: "var(--control-height-small)",
            background: "var(--panel)",
            border: "1px solid var(--dim)",
            borderRadius: 2,
            padding: "0 10px",
            color: "var(--white)",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            outline: "none",
          }}
        />

        {/* Severity filter chips */}
        {["critical", "high", "medium", "low"].map((s) => (
          <button
            key={s}
            className={`btn btn-small ${severityFilter === s ? "btn-primary" : "btn-neutral"}`}
            onClick={() => { setSeverityFilter(severityFilter === s ? null : s); setPage(0); }}
            style={{ fontSize: "var(--font-size-label)" }}
          >
            {s}
          </button>
        ))}

        {[
          ["all_related", "All Related"],
          ["observed_successful", "Observed Successful"],
          ["observation_failed", "Observation Failed"],
          ["not_yet_observed", "Unobserved Discovered"],
          ["third_party_linked", "Third-Party Linked"],
          ["historical_or_ct_only", "Historical / CT-Only"],
        ].map(([value, label]) => (
          <button
            key={value}
            className={`btn btn-small ${surfaceFilter === value ? "btn-primary" : "btn-neutral"}`}
            onClick={() => { setSurfaceFilter(value); setPage(0); }}
            style={{ fontSize: "var(--font-size-label)" }}
          >
            {label}
          </button>
        ))}

        <div style={{ flex: 1 }} />

        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--muted)",
          }}
        >
          {sorted.length} endpoints
        </span>

        <button className="btn btn-small btn-neutral" onClick={handleExport}>
          Export CSV
        </button>
      </div>

      {endpointRowsTruncated && (
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-label)",
            color: "var(--muted)",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          Endpoint surface is truncated. Increase endpoint pagination fetch limits to inspect the full set.
        </div>
      )}
      </div>

      <div className="g-scroll-page__body">
        <div style={{ border: "1px solid var(--border)" }}>
        {/* Header */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: gridCols,
            gap: 8,
            padding: "8px 12px",
            background: "var(--panel)",
            borderBottom: "1px solid var(--border)",
          }}
        >
          {COLUMNS.map((col) => (
            <span
              key={col.key}
              onClick={() => handleSort(col.key)}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "var(--font-size-label)",
                letterSpacing: "0.2em",
                textTransform: "uppercase",
                color: sortKey === col.key ? "var(--white)" : "var(--muted)",
                cursor: "pointer",
                userSelect: "none",
              }}
            >
              {col.label}
              {sortKey === col.key && (sortAsc ? " ^" : " v")}
            </span>
          ))}
        </div>

        {/* Rows */}
        {paged.map((ep) => {
          const band = severityBand(ep.guardian_risk);
          return (
            <div
              key={ep.entity_id}
              onClick={() => navigate(endpointDetailPath(ep.entity_id))}
              style={{
                display: "grid",
                gridTemplateColumns: gridCols,
                gap: 8,
                padding: "8px 12px",
                borderBottom: "1px solid var(--border)",
                cursor: "pointer",
                fontFamily: "var(--font-mono)",
                fontSize: "var(--font-size-caption)",
                color: "var(--white)",
                transition: "background 0.1s",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--surface)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {ep.entity_id}
              </span>
              <span style={{ color: "var(--ghost)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {ep.hostname}
              </span>
              <span style={{ color: "var(--ghost)" }}>{ep.port}</span>
              <span style={{ color: "var(--ghost)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: "var(--font-size-label)" }}>
                {formatObservationStatus(ep.observation_status)}
              </span>
              <span style={{ color: "var(--ghost)", textTransform: "uppercase", letterSpacing: "0.08em", fontSize: "var(--font-size-label)" }}>
                {formatOwnershipLabel(ep.ownership_category, "short")}
              </span>
              <span style={{ color: "var(--ghost)" }}>{formatScore(ep.relevance_score)}</span>
              <span style={{ color: severityColor(band) }}>{formatScore(ep.guardian_risk)}</span>
              <span style={{ color: "var(--ghost)" }}>{formatScore(ep.confidence)}</span>
              <span>{ep.alert_count}</span>
              <span style={{ color: "var(--ghost)" }}>{ep.tls_version || "-"}</span>
              <span style={{ color: "var(--ghost)" }}>{formatRelativeTime(ep.last_seen_ms)}</span>
            </div>
          );
        })}

        {paged.length === 0 && <div className="g-empty">No endpoints match filters</div>}
      </div>
      </div>

      {totalPages > 1 && (
        <div className="g-scroll-page__footer">
        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            alignItems: "center",
            gap: 8,
            padding: "8px 0",
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-caption)",
            color: "var(--muted)",
          }}
        >
          <span>
            {page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, sorted.length)} of {sorted.length}
          </span>
          <button className="btn btn-small btn-neutral" disabled={page === 0} onClick={() => setPage(page - 1)}>
            Prev
          </button>
          <button className="btn btn-small btn-neutral" disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>
            Next
          </button>
        </div>
        </div>
      )}
    </div>
  );
}

function formatObservationStatus(status: string): string {
  switch (status) {
    case "observed_successful":
      return "Observed";
    case "observation_failed":
      return "Failed";
    case "historical_or_ct_only":
      return "Historical";
    case "not_yet_observed":
      return "Discovered";
    default:
      return status || "-";
  }
}
