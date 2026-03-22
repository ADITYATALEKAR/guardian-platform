import {
  startTransition,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
  type CSSProperties,
  type MouseEvent as ReactMouseEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import {
  MAX_RENDER_EDGES,
  MAX_RENDER_NODES,
  buildDeterministicLayout,
  collectFocusNeighborhood,
  findRoute,
  getDistrictMeta,
  getEdgeMeta,
  parseGraphSnapshot,
  type DisplayDistrict,
  type DisplayNode,
  type GraphViewMode,
} from "./graph-model";
import { formatTimestamp } from "../lib/formatters";
import "./graph-viewer.css";

type GraphViewerProps = {
  snapshot: unknown;
  width?: number;
  height?: number;
  onNodeSelect?: (nodeId: string) => void;
  focusNodeId?: string;
  compact?: boolean;
};

type DragState = {
  startX: number;
  startY: number;
  panX: number;
  panY: number;
};

type Point = { x: number; y: number };

const VIEW_LABELS: Record<GraphViewMode, string> = {
  overview: "Overview",
  focus: "Focus",
  route: "Route",
};

const FOCUS_SCOPE_OPTIONS = [1, 2];

export function GraphViewer({
  snapshot,
  width = 920,
  height = 520,
  onNodeSelect,
  focusNodeId,
  compact,
}: GraphViewerProps) {
  const parsed = useMemo(() => parseGraphSnapshot(snapshot), [snapshot]);
  const graph = parsed.kind === "ok" ? parsed.graph : null;
  const compactMode = compact ?? width <= 760;

  const [selectedNodeId, setSelectedNodeId] = useState("");
  const [selectedEdgeId, setSelectedEdgeId] = useState("");
  const [hoverNodeId, setHoverNodeId] = useState("");
  const [hoverEdgeId, setHoverEdgeId] = useState("");
  const [mode, setMode] = useState<GraphViewMode>(focusNodeId ? "focus" : "overview");
  const [focusScope, setFocusScope] = useState(1);
  const [enabledEdgeTypes, setEnabledEdgeTypes] = useState<Set<string>>(new Set());
  const [searchValue, setSearchValue] = useState("");
  const deferredSearch = useDeferredValue(searchValue.trim().toLowerCase());
  const [routeStartId, setRouteStartId] = useState("");
  const [routeEndId, setRouteEndId] = useState("");
  const [zoom, setZoom] = useState(1);
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [drag, setDrag] = useState<DragState | null>(null);

  useEffect(() => {
    if (!graph) return;
    setEnabledEdgeTypes(new Set(graph.edgeTypes));
  }, [graph]);

  useEffect(() => {
    if (!focusNodeId || !graph?.nodeById.has(focusNodeId)) return;
    setSelectedNodeId(focusNodeId);
    setMode((current) => (current === "overview" ? "focus" : current));
  }, [focusNodeId, graph]);

  const pinnedNodeIds = useMemo(() => {
    const pins = [focusNodeId, routeStartId, routeEndId];
    if (graph?.nodeById.has(selectedNodeId)) pins.push(selectedNodeId);
    return [...new Set(pins.filter((pin): pin is string => Boolean(pin)))];
  }, [focusNodeId, graph, routeEndId, routeStartId, selectedNodeId]);

  const layout = useMemo(() => {
    if (!graph || enabledEdgeTypes.size === 0) return null;
    return buildDeterministicLayout(graph, {
      width,
      height,
      enabledEdgeTypes,
      pinnedNodeIds,
    });
  }, [enabledEdgeTypes, graph, height, pinnedNodeIds, width]);

  const searchMatches = useMemo(() => {
    if (!graph || !deferredSearch) return [];
    return graph.nodes
      .filter((node) => node.searchableText.includes(deferredSearch))
      .sort((left, right) => {
        const leftStarts = left.searchableText.startsWith(deferredSearch) ? 1 : 0;
        const rightStarts = right.searchableText.startsWith(deferredSearch) ? 1 : 0;
        if (rightStarts !== leftStarts) return rightStarts - leftStarts;
        if (right.importance !== left.importance) return right.importance - left.importance;
        return left.label.localeCompare(right.label);
      })
      .slice(0, 7);
  }, [deferredSearch, graph]);

  const searchDisplayIds = useMemo(() => {
    const ids = new Set<string>();
    if (!layout) return ids;
    for (const node of searchMatches) {
      ids.add(layout.rawToDisplayNodeId.get(node.id) ?? node.id);
    }
    return ids;
  }, [layout, searchMatches]);

  const focusAnchorId = useMemo(() => {
    if (!graph) return "";
    if (graph.nodeById.has(selectedNodeId)) return selectedNodeId;
    if (focusNodeId && graph.nodeById.has(focusNodeId)) return focusNodeId;
    return "";
  }, [focusNodeId, graph, selectedNodeId]);

  const focusNeighborhood = useMemo(() => {
    if (!graph || mode !== "focus" || !focusAnchorId) return null;
    return collectFocusNeighborhood(graph, focusAnchorId, focusScope, enabledEdgeTypes);
  }, [enabledEdgeTypes, focusAnchorId, focusScope, graph, mode]);

  const routeResult = useMemo(() => {
    if (!graph || mode !== "route" || !routeStartId || !routeEndId) return null;
    return findRoute(graph, routeStartId, routeEndId, enabledEdgeTypes);
  }, [enabledEdgeTypes, graph, mode, routeEndId, routeStartId]);

  const activeNodeIds = useMemo(() => {
    const ids = new Set<string>();
    if (!layout) return ids;
    if (mode === "overview") {
      layout.nodes.forEach((node) => ids.add(node.id));
      return ids;
    }

    const rawIds =
      mode === "focus" ? focusNeighborhood?.nodeIds : mode === "route" ? new Set(routeResult?.nodeIds ?? []) : null;
    if (!rawIds || rawIds.size === 0) return ids;
    rawIds.forEach((rawId) => ids.add(layout.rawToDisplayNodeId.get(rawId) ?? rawId));
    if (selectedNodeId) ids.add(selectedNodeId);
    return ids;
  }, [focusNeighborhood, layout, mode, routeResult, selectedNodeId]);

  const activeEdgeIds = useMemo(() => {
    const ids = new Set<string>();
    if (!layout) return ids;
    if (mode === "overview") {
      layout.edges.forEach((edge) => ids.add(edge.id));
      return ids;
    }
    const rawEdgeIds =
      mode === "focus" ? focusNeighborhood?.edgeIds : mode === "route" ? new Set(routeResult?.edgeIds ?? []) : null;
    if (!rawEdgeIds || rawEdgeIds.size === 0) return ids;
    for (const edge of layout.edges) {
      if (edge.memberEdgeIds.some((edgeId) => rawEdgeIds.has(edgeId))) ids.add(edge.id);
    }
    return ids;
  }, [focusNeighborhood, layout, mode, routeResult]);

  const selectedNode = layout?.nodeById.get(selectedNodeId) ?? null;
  const selectedEdge = layout?.edgeById.get(selectedEdgeId) ?? null;
  const routeStartLabel = graph?.nodeById.get(routeStartId)?.label ?? routeStartId;
  const routeEndLabel = graph?.nodeById.get(routeEndId)?.label ?? routeEndId;

  if (parsed.kind === "empty") {
    return <div style={S.statePanel}>Graph unavailable for this cycle</div>;
  }
  if (parsed.kind === "invalid") {
    return <div style={S.statePanel}>Graph payload invalid</div>;
  }
  if (!graph || !layout) {
    return <div style={S.statePanel}>Graph unavailable for this cycle</div>;
  }

  function resetView() {
    setZoom(1);
    setPanX(0);
    setPanY(0);
  }

  function toggleEdgeType(edgeType: string) {
    startTransition(() => {
      setEnabledEdgeTypes((current) => {
        const next = new Set(current);
        if (next.has(edgeType)) next.delete(edgeType);
        else next.add(edgeType);
        return next.size === 0 ? new Set(current) : next;
      });
      setSelectedEdgeId("");
    });
  }

  function selectMode(nextMode: GraphViewMode) {
    setMode(nextMode);
    setSelectedEdgeId("");
    if (nextMode !== "route") {
      setRouteStartId("");
      setRouteEndId("");
    }
  }

  function handleNodeSelection(node: DisplayNode) {
    if (!graph) return;
    setSelectedEdgeId("");
    setSelectedNodeId(node.id);

    const rawId = graph.nodeById.has(node.id) ? node.id : "";
    if (mode === "route" && rawId) {
      if (!routeStartId || routeEndId) {
        setRouteStartId(rawId);
        setRouteEndId("");
      } else if (routeStartId !== rawId) {
        setRouteEndId(rawId);
      }
    }

    if (!node.aggregate && rawId) onNodeSelect?.(rawId);
  }

  function selectSearchMatch(nodeId: string) {
    setSelectedEdgeId("");
    setSelectedNodeId(nodeId);
    if (mode === "route") {
      if (!routeStartId || routeEndId) {
        setRouteStartId(nodeId);
        setRouteEndId("");
      } else if (routeStartId !== nodeId) {
        setRouteEndId(nodeId);
      }
    } else {
      onNodeSelect?.(nodeId);
    }
  }

  function handleMouseDown(event: ReactMouseEvent<SVGSVGElement>) {
    setDrag({
      startX: event.clientX,
      startY: event.clientY,
      panX,
      panY,
    });
  }

  function handleMouseMove(event: ReactMouseEvent<SVGSVGElement>) {
    if (!drag) return;
    setPanX(clamp(drag.panX + event.clientX - drag.startX, -width * 0.5, width * 0.5));
    setPanY(clamp(drag.panY + event.clientY - drag.startY, -height * 0.5, height * 0.5));
  }

  function handleWheel(event: ReactWheelEvent<SVGSVGElement>) {
    event.preventDefault();
    setZoom((current) => clamp(current + (event.deltaY < 0 ? 0.12 : -0.12), 0.65, 2.2));
  }

  const miniMapScaleX = 120 / width;
  const miniMapScaleY = 88 / height;

  return (
    <section className={`graph-viewer${compactMode ? " graph-viewer--compact" : ""}`}>
      <div className="graph-viewer__surface">
        <div className="graph-viewer__topbar">
          <div className="graph-viewer__summary">
            <div>
              <div className="graph-viewer__eyebrow">Dependency Map</div>
              <div className="graph-viewer__headline">Trust graph as districts, roads, and buildings</div>
            </div>
            <div className="graph-viewer__meta">
              {graph.nodes.length} raw nodes · {graph.edges.length} raw edges · render caps {MAX_RENDER_NODES}/
              {MAX_RENDER_EDGES}
            </div>
          </div>

          <div className="graph-viewer__controls">
            <div className="graph-viewer__toolbar-group">
              <div className="graph-viewer__search">
                <input
                  className="graph-viewer__search-input"
                  value={searchValue}
                  onChange={(event) => setSearchValue(event.target.value)}
                  placeholder="Search endpoints, evidence kinds, identities, hashes..."
                />
                {searchMatches.length > 0 && (
                  <div className="graph-viewer__search-results">
                    {searchMatches.map((node) => (
                      <button
                        key={node.id}
                        className="graph-viewer__search-result"
                        onClick={() => selectSearchMatch(node.id)}
                      >
                        <span className="graph-viewer__search-title">{node.label}</span>
                        <span className="graph-viewer__search-type">{getDistrictMeta(node.districtKey).label}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="graph-viewer__toggles">
                {(["overview", "focus", "route"] as GraphViewMode[]).map((viewMode) => (
                  <button
                    key={viewMode}
                    className={`graph-viewer__chip${mode === viewMode ? " is-active" : ""}`}
                    onClick={() => selectMode(viewMode)}
                  >
                    {VIEW_LABELS[viewMode]}
                  </button>
                ))}
                {mode === "focus" && (
                  <label className="graph-viewer__scope">
                    Scope
                    <select
                      className="graph-viewer__scope-select"
                      value={focusScope}
                      onChange={(event) => setFocusScope(Number(event.target.value))}
                    >
                      {FOCUS_SCOPE_OPTIONS.map((option) => (
                        <option key={option} value={option}>
                          {option} hop{option === 1 ? "" : "s"}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
                {mode === "route" && (
                  <button
                    className="graph-viewer__chip"
                    onClick={() => {
                      setRouteStartId("");
                      setRouteEndId("");
                    }}
                  >
                    Clear Route
                  </button>
                )}
              </div>
            </div>

            <div className="graph-viewer__toolbar-group">
              <div className="graph-viewer__eyebrow">Edge Types</div>
              <div className="graph-viewer__filters">
                {graph.edgeTypes.map((edgeType) => (
                  <button
                    key={edgeType}
                    className={`graph-viewer__chip graph-viewer__chip--edge${
                      enabledEdgeTypes.has(edgeType) ? " is-active" : ""
                    }`}
                    onClick={() => toggleEdgeType(edgeType)}
                  >
                    <span
                      className="graph-viewer__chip-dot"
                      style={{ background: getEdgeMeta(edgeType).color }}
                    />
                    {getEdgeMeta(edgeType).label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="graph-viewer__canvas-wrap">
          <svg
            width={width}
            height={height}
            className={`graph-viewer__canvas${drag ? " is-dragging" : ""}`}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={() => setDrag(null)}
            onMouseLeave={() => setDrag(null)}
            onWheel={handleWheel}
          >
            <defs>
              <pattern id="guardianGraphGrid" width="34" height="34" patternUnits="userSpaceOnUse">
                <path d="M 34 0 L 0 0 0 34" fill="none" stroke="#0f1720" strokeWidth="0.7" />
              </pattern>
              <filter id="guardianGlow">
                <feGaussianBlur stdDeviation="5" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <rect width={width} height={height} fill="url(#guardianGraphGrid)" />

            <g transform={`translate(${panX}, ${panY}) scale(${zoom})`}>
              {layout.districtLinks.map((link) => {
                const sourceDistrict = layout.districts.find((district) => district.key === link.sourceDistrict);
                const targetDistrict = layout.districts.find((district) => district.key === link.targetDistrict);
                if (!sourceDistrict || !targetDistrict) return null;
                const path = buildRoadPath(
                  districtCenter(sourceDistrict),
                  districtCenter(targetDistrict),
                  0.28,
                );
                return (
                  <path
                    key={link.id}
                    d={path}
                    fill="none"
                    stroke="rgba(53, 120, 179, 0.22)"
                    strokeWidth={clamp(2 + link.count * 0.22, 2.5, 10)}
                    strokeLinecap="round"
                    filter="url(#guardianGlow)"
                    opacity={mode === "overview" ? 0.55 : 0.18}
                  />
                );
              })}

              {layout.districts.map((district) => {
                const districtActive =
                  mode === "overview" ||
                  district.nodeIds.some((nodeId) => activeNodeIds.has(nodeId)) ||
                  district.nodeIds.some((nodeId) => searchDisplayIds.has(nodeId));
                return (
                  <g key={district.key}>
                    <rect
                      x={district.x}
                      y={district.y}
                      width={district.w}
                      height={district.h}
                      rx={10}
                      fill={districtActive ? "rgba(12, 18, 26, 0.9)" : "rgba(10, 13, 18, 0.82)"}
                      stroke={district.color}
                      strokeOpacity={districtActive ? 0.45 : 0.22}
                      strokeWidth={districtActive ? 1.2 : 0.8}
                    />
                    <rect
                      x={district.x}
                      y={district.y}
                      width={district.w}
                      height={24}
                      rx={10}
                      fill="rgba(255,255,255,0.03)"
                    />
                    <rect
                      x={district.x}
                      y={district.y}
                      width={6}
                      height={district.h}
                      rx={3}
                      fill={district.color}
                      opacity={0.8}
                    />
                    <text x={district.x + 16} y={district.y + 15} style={S.districtLabel}>
                      {district.label.toUpperCase()}
                    </text>
                    <text
                      x={district.x + district.w - 12}
                      y={district.y + 15}
                      textAnchor="end"
                      style={S.districtCount}
                    >
                      {district.totalNodes} nodes
                    </text>
                    {district.hiddenNodes > 0 && (
                      <text
                        x={district.x + district.w - 12}
                        y={district.y + district.h - 10}
                        textAnchor="end"
                        style={S.overflowLabel}
                      >
                        {district.hiddenNodes} aggregated
                      </text>
                    )}
                  </g>
                );
              })}

              {layout.edges.map((edge) => {
                const source = layout.nodeById.get(edge.source);
                const target = layout.nodeById.get(edge.target);
                if (!source || !target) return null;
                const path = buildRoadPath(
                  { x: source.x, y: source.y },
                  { x: target.x, y: target.y },
                  source.districtKey === target.districtKey ? 0.16 : 0.34,
                );
                const active = activeEdgeIds.has(edge.id);
                const selected = selectedEdgeId === edge.id;
                const hovered = hoverEdgeId === edge.id;
                const strokeOpacity =
                  mode === "overview" ? (selected || hovered ? 0.92 : 0.34) : active ? 0.9 : 0.08;
                return (
                  <g key={edge.id}>
                    <path
                      d={path}
                      fill="none"
                      stroke={edge.color}
                      strokeOpacity={strokeOpacity}
                      strokeWidth={selected ? 3.8 : hovered ? 3.2 : clamp(1 + edge.count * 0.2, 1.2, 4.6)}
                      strokeLinecap="round"
                      strokeDasharray={edge.dashArray}
                    />
                    <path
                      d={path}
                      fill="none"
                      stroke="transparent"
                      strokeWidth={12}
                      onMouseEnter={() => setHoverEdgeId(edge.id)}
                      onMouseLeave={() => setHoverEdgeId("")}
                      onClick={() => {
                        setSelectedNodeId("");
                        setSelectedEdgeId(edge.id);
                      }}
                    />
                  </g>
                );
              })}

              {layout.nodes.map((node) => {
                const searchMatched = searchDisplayIds.has(node.id);
                const active = mode === "overview" ? true : activeNodeIds.has(node.id);
                const selected = selectedNodeId === node.id;
                const hovered = hoverNodeId === node.id;
                const buildingFill = selected
                  ? "rgba(255,255,255,0.16)"
                  : hovered
                    ? "rgba(255,255,255,0.12)"
                    : node.aggregate
                      ? "rgba(255,255,255,0.05)"
                      : "rgba(255,255,255,0.07)";
                const opacity = active ? 1 : 0.2;
                const labelVisible =
                  selected ||
                  hovered ||
                  searchMatched ||
                  node.aggregate ||
                  node.width > 70 ||
                  node.importance >= 9.5;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x - node.width / 2}, ${node.y - node.height / 2})`}
                    opacity={opacity}
                    onMouseEnter={() => setHoverNodeId(node.id)}
                    onMouseLeave={() => setHoverNodeId("")}
                    onClick={() => handleNodeSelection(node)}
                    style={{ cursor: "pointer" }}
                  >
                    <rect
                      width={node.width}
                      height={node.height}
                      rx={node.aggregate ? 14 : 7}
                      fill={buildingFill}
                      stroke={searchMatched ? "#ffffff" : node.color}
                      strokeOpacity={selected || searchMatched ? 0.9 : 0.42}
                      strokeWidth={selected ? 1.8 : 1}
                    />
                    <rect width={node.width} height={4} rx={2} fill={node.color} opacity={0.9} />
                    <rect
                      x={6}
                      y={Math.max(7, node.height - 8)}
                      width={node.width - 12}
                      height={1}
                      fill="rgba(255,255,255,0.08)"
                    />
                    {labelVisible && (
                      <text x={8} y={node.height / 2 + 3} style={S.nodeLabel}>
                        {truncate(node.shortLabel, Math.max(10, Math.floor(node.width / 5)))}
                      </text>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          <div className="graph-viewer__mini-map">
            <div className="graph-viewer__mini-title">District Map</div>
            <svg width="132" height="96">
              {layout.districts.map((district) => {
                const active =
                  mode === "overview" ||
                  district.nodeIds.some((nodeId) => activeNodeIds.has(nodeId)) ||
                  district.nodeIds.some((nodeId) => searchDisplayIds.has(nodeId));
                return (
                  <rect
                    key={district.key}
                    x={district.x * miniMapScaleX}
                    y={district.y * miniMapScaleY}
                    width={district.w * miniMapScaleX}
                    height={district.h * miniMapScaleY}
                    rx={4}
                    fill={active ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.04)"}
                    stroke={district.color}
                    strokeOpacity={0.7}
                  />
                );
              })}
            </svg>
          </div>

          <div className="graph-viewer__canvas-footer">
            <div className="graph-viewer__legend">
              {layout.districts.map((district) => (
                <div key={district.key} className="graph-viewer__legend-item">
                  <span className="graph-viewer__legend-swatch" style={{ background: district.color }} />
                  <span>{district.label}</span>
                  <span>{district.totalNodes}</span>
                </div>
              ))}
            </div>
            <div className="graph-viewer__canvas-actions">
              <button className="btn btn-neutral" onClick={() => setZoom((current) => clamp(current - 0.15, 0.65, 2.2))}>
                Zoom -
              </button>
              <button className="btn btn-neutral" onClick={() => setZoom((current) => clamp(current + 0.15, 0.65, 2.2))}>
                Zoom +
              </button>
              <button className="btn btn-neutral" onClick={resetView}>
                Reset
              </button>
            </div>
          </div>
        </div>
      </div>

      <aside className="graph-viewer__panel">
        <section className="graph-viewer__card">
          <div className="graph-viewer__card-title">Snapshot</div>
          <div className="graph-viewer__stat-grid">
            <div className="graph-viewer__stat">
              <div className="graph-viewer__stat-label">Rendered Nodes</div>
              <div className="graph-viewer__stat-value">{layout.nodes.length}</div>
            </div>
            <div className="graph-viewer__stat">
              <div className="graph-viewer__stat-label">Rendered Roads</div>
              <div className="graph-viewer__stat-value">{layout.edges.length}</div>
            </div>
            <div className="graph-viewer__stat">
              <div className="graph-viewer__stat-label">Active Mode</div>
              <div className="graph-viewer__stat-value">{VIEW_LABELS[mode]}</div>
            </div>
            <div className="graph-viewer__stat">
              <div className="graph-viewer__stat-label">Created</div>
              <div className="graph-viewer__stat-value" style={{ fontSize: 12 }}>
                {formatTimestamp(graph.createdAtMs)}
              </div>
            </div>
          </div>
        </section>

        <section className="graph-viewer__card">
          <div className="graph-viewer__card-title">Route</div>
          <div className="graph-viewer__detail-grid">
            <DetailKV label="Start" value={routeStartLabel || "Click a node in route mode"} />
            <DetailKV label="End" value={routeEndLabel || "Pick a second node"} />
            {mode === "route" && routeStartId && routeEndId && !routeResult && (
              <div className="graph-viewer__hint">No structural path found across the enabled edge types.</div>
            )}
            {routeResult && (
              <div className="graph-viewer__route-list">
                {routeResult.nodeIds.map((nodeId) => (
                  <span key={nodeId} className="graph-viewer__pill">
                    {graph.nodeById.get(nodeId)?.shortLabel ?? nodeId}
                  </span>
                ))}
              </div>
            )}
          </div>
        </section>

        <section className="graph-viewer__card">
          <div className="graph-viewer__card-title">Inspector</div>
          {selectedNode && (
            <>
              <div className="graph-viewer__detail-title">{selectedNode.label}</div>
              <div className="graph-viewer__detail-subtitle">
                {selectedNode.aggregate
                  ? `${getDistrictMeta(selectedNode.districtKey).label} aggregate`
                  : getDistrictMeta(selectedNode.districtKey).label}
              </div>
              <div className="graph-viewer__detail-grid">
                <DetailKV label="Node Type" value={selectedNode.nodeType} />
                <DetailKV label="District" value={getDistrictMeta(selectedNode.districtKey).label} />
                <DetailKV label="Cluster" value={selectedNode.clusterLabel} />
                <DetailKV label="Degree" value={String(selectedNode.degree)} />
                {selectedNode.aggregate ? (
                  <DetailKV label="Members" value={String(selectedNode.memberNodeIds.length)} />
                ) : (
                  <DetailKV label="Node Id" value={selectedNode.id} />
                )}
                {!selectedNode.aggregate && (
                  <div className="graph-viewer__detail-actions">
                    <button className="btn btn-small btn-neutral" onClick={() => setMode("focus")}>
                      Focus Here
                    </button>
                    <button
                      className="btn btn-small btn-neutral"
                      onClick={() => {
                        setMode("route");
                        setRouteStartId(selectedNode.id);
                        setRouteEndId("");
                      }}
                    >
                      Route From
                    </button>
                    <button
                      className="btn btn-small btn-neutral"
                      onClick={() => {
                        setMode("route");
                        if (!routeStartId) setRouteStartId(selectedNode.id);
                        else setRouteEndId(selectedNode.id);
                      }}
                    >
                      Route To
                    </button>
                  </div>
                )}
                {selectedNode.aggregate && (
                  <div className="graph-viewer__member-list">
                    {selectedNode.memberNodeIds.slice(0, 8).map((memberId) => (
                      <span key={memberId} className="graph-viewer__pill">
                        {graph.nodeById.get(memberId)?.shortLabel ?? memberId}
                      </span>
                    ))}
                    {selectedNode.memberNodeIds.length > 8 && (
                      <span className="graph-viewer__pill">+{selectedNode.memberNodeIds.length - 8} more</span>
                    )}
                  </div>
                )}
              </div>
            </>
          )}

          {!selectedNode && selectedEdge && (
            <>
              <div className="graph-viewer__detail-title">{getEdgeMeta(selectedEdge.edgeType).label}</div>
              <div className="graph-viewer__detail-subtitle">
                {layout.nodeById.get(selectedEdge.source)?.label} → {layout.nodeById.get(selectedEdge.target)?.label}
              </div>
              <div className="graph-viewer__detail-grid">
                <DetailKV label="Count" value={String(selectedEdge.count)} />
                <DetailKV label="Weight" value={selectedEdge.weight.toFixed(2)} />
                <DetailKV label="First Seen" value={selectedEdge.firstSeenMs ? formatTimestamp(selectedEdge.firstSeenMs) : "-"} />
                <DetailKV label="Last Seen" value={selectedEdge.lastSeenMs ? formatTimestamp(selectedEdge.lastSeenMs) : "-"} />
                <DetailKV
                  label="District Span"
                  value={`${getDistrictMeta(selectedEdge.sourceDistrict).label} → ${getDistrictMeta(selectedEdge.targetDistrict).label}`}
                />
              </div>
            </>
          )}

          {!selectedNode && !selectedEdge && (
            <div className="graph-viewer__hint">
              Click a building to inspect a node, or click a road to inspect a dependency edge. In route mode,
              click two real nodes to trace the shortest visible structural path.
            </div>
          )}
        </section>
      </aside>
    </section>
  );
}

function DetailKV({ label, value }: { label: string; value: string }) {
  return (
    <div className="graph-viewer__kv">
      <div className="graph-viewer__kv-key">{label}</div>
      <div className="graph-viewer__kv-value">{value}</div>
    </div>
  );
}

function buildRoadPath(from: Point, to: Point, curvature: number) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const mx = from.x + dx / 2;
  const my = from.y + dy / 2;
  const distance = Math.hypot(dx, dy) || 1;
  const normalX = (-dy / distance) * distance * curvature;
  const normalY = (dx / distance) * distance * curvature;
  return `M ${from.x} ${from.y} Q ${mx + normalX} ${my + normalY} ${to.x} ${to.y}`;
}

function districtCenter(district: DisplayDistrict): Point {
  return { x: district.x + district.w / 2, y: district.y + district.h / 2 };
}

function truncate(value: string, max: number) {
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}

function clamp(value: number, min: number, max: number) {
  return value < min ? min : value > max ? max : value;
}

const S: Record<string, CSSProperties> = {
  districtLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 9,
    letterSpacing: "0.18em",
    fill: "#b7c4d6",
  },
  districtCount: {
    fontFamily: "var(--font-mono)",
    fontSize: 9,
    fill: "#68778d",
  },
  overflowLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 8,
    fill: "#5a6779",
    letterSpacing: "0.12em",
  },
  nodeLabel: {
    fontFamily: "var(--font-mono)",
    fontSize: 8,
    letterSpacing: "0.06em",
    fill: "#f5f8ff",
  },
  statePanel: {
    border: "1px solid var(--color-border)",
    backgroundColor: "#090c12",
    padding: 12,
    fontSize: "var(--font-size-secondary)",
    color: "var(--color-text-secondary)",
  },
};
