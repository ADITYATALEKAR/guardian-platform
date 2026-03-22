export const MAX_RENDER_NODES = 120;
export const MAX_RENDER_EDGES = 360;

export type GraphViewMode = "overview" | "focus" | "route";

export type ParsedGraphNode = {
  id: string;
  label: string;
  shortLabel: string;
  nodeType: string;
  districtKey: string;
  clusterKey: string;
  clusterLabel: string;
  searchableText: string;
  metadata: Record<string, unknown>;
  kind: string;
  hash: string;
  entityId: string;
  degree: number;
  inDegree: number;
  outDegree: number;
  importance: number;
};

export type ParsedGraphEdge = {
  id: string;
  source: string;
  target: string;
  edgeType: string;
  weight: number;
  count: number;
  firstSeenMs: number | null;
  lastSeenMs: number | null;
  metadata: Record<string, unknown>;
};

export type ParsedGraph = {
  version: number;
  createdAtMs: number;
  nodes: ParsedGraphNode[];
  edges: ParsedGraphEdge[];
  nodeById: Map<string, ParsedGraphNode>;
  edgeById: Map<string, ParsedGraphEdge>;
  edgeTypes: string[];
  districtKeys: string[];
  outgoing: Map<string, ParsedGraphEdge[]>;
  incoming: Map<string, ParsedGraphEdge[]>;
  undirected: Map<string, ParsedGraphEdge[]>;
};

export type GraphParseResult =
  | { kind: "empty" }
  | { kind: "invalid" }
  | { kind: "ok"; graph: ParsedGraph };

export type DisplayNode = {
  id: string;
  label: string;
  shortLabel: string;
  nodeType: string;
  districtKey: string;
  clusterKey: string;
  clusterLabel: string;
  color: string;
  metadata: Record<string, unknown>;
  importance: number;
  degree: number;
  inDegree: number;
  outDegree: number;
  aggregate: boolean;
  hiddenCount: number;
  memberNodeIds: string[];
  x: number;
  y: number;
  width: number;
  height: number;
};

export type DisplayEdge = {
  id: string;
  source: string;
  target: string;
  edgeType: string;
  count: number;
  weight: number;
  firstSeenMs: number | null;
  lastSeenMs: number | null;
  color: string;
  dashArray: string;
  aggregate: boolean;
  memberEdgeIds: string[];
  sourceDistrict: string;
  targetDistrict: string;
  metadata: Record<string, unknown>;
};

export type DisplayDistrict = {
  key: string;
  label: string;
  color: string;
  nodeType: string;
  totalNodes: number;
  hiddenNodes: number;
  clusterCount: number;
  x: number;
  y: number;
  w: number;
  h: number;
  nodeIds: string[];
};

export type DistrictLink = {
  id: string;
  sourceDistrict: string;
  targetDistrict: string;
  count: number;
  weight: number;
  edgeTypes: string[];
};

export type GraphRenderModel = {
  nodes: DisplayNode[];
  edges: DisplayEdge[];
  districts: DisplayDistrict[];
  districtLinks: DistrictLink[];
  nodeById: Map<string, DisplayNode>;
  edgeById: Map<string, DisplayEdge>;
  rawToDisplayNodeId: Map<string, string>;
};

type DistrictMeta = {
  label: string;
  color: string;
  order: number;
};

type EdgeMeta = {
  label: string;
  color: string;
  dashArray: string;
};

const DISTRICT_META: Record<string, DistrictMeta> = {
  endpoint: { label: "Endpoints", color: "#53c7f2", order: 0 },
  session: { label: "Sessions", color: "#7f7af9", order: 1 },
  identity: { label: "Identities", color: "#39d98a", order: 2 },
  trust_material: { label: "Trust Material", color: "#f0b429", order: 3 },
  evidence: { label: "Evidence", color: "#f97352", order: 4 },
  other: { label: "Other Nodes", color: "#7a8699", order: 5 },
};

const EDGE_META: Record<string, EdgeMeta> = {
  produces: { label: "Produces", color: "#f97352", dashArray: "" },
  identity_link: { label: "Identity Link", color: "#39d98a", dashArray: "" },
  material_dependency: { label: "Material Dependency", color: "#f0b429", dashArray: "" },
  temporal_sequence: { label: "Temporal Sequence", color: "#7f7af9", dashArray: "7 5" },
  vector_similarity: { label: "Vector Similarity", color: "#69c0ff", dashArray: "3 6" },
  depends_on: { label: "Depends On", color: "#8bc1ff", dashArray: "" },
  connects_to: { label: "Connects To", color: "#7a8699", dashArray: "" },
  uses_identity: { label: "Uses Identity", color: "#39d98a", dashArray: "" },
  uses_trust_material: { label: "Uses Trust Material", color: "#f0b429", dashArray: "" },
  emits_evidence: { label: "Emits Evidence", color: "#f97352", dashArray: "" },
  issued_by: { label: "Issued By", color: "#f0b429", dashArray: "" },
  other: { label: "Linked", color: "#7a8699", dashArray: "" },
};

type DistrictFrame = {
  key: string;
  x: number;
  y: number;
  w: number;
  h: number;
};

export function getDistrictMeta(key: string): DistrictMeta {
  return DISTRICT_META[key] ?? DISTRICT_META.other;
}

export function getEdgeMeta(key: string): EdgeMeta {
  return EDGE_META[key] ?? EDGE_META.other;
}

export function seededRandom(seed: number) {
  let value = seed >>> 0;
  return () => {
    value += 0x6d2b79f5;
    let t = value;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function parseGraphSnapshot(input: unknown): GraphParseResult {
  const payload = asRecord(input);
  if (!payload || Object.keys(payload).length === 0) return { kind: "empty" };

  const version = toNumber(payload.version);
  const createdAtMs = toNumber(payload.created_at_ms);
  const nodesRaw = Array.isArray(payload.nodes) ? payload.nodes : null;
  const edgesRaw = Array.isArray(payload.edges) ? payload.edges : null;

  if (!Number.isFinite(version) || !Number.isFinite(createdAtMs) || !nodesRaw || !edgesRaw) {
    return { kind: "invalid" };
  }

  const baseNodes: Array<{
    id: string;
    label: string;
    shortLabel: string;
    nodeType: string;
    districtKey: string;
    clusterKey: string;
    clusterLabel: string;
    searchableText: string;
    metadata: Record<string, unknown>;
    kind: string;
    hash: string;
    entityId: string;
  }> = [];

  for (const row of nodesRaw) {
    const obj = asRecord(row);
    const id = toString(obj?.id ?? obj?.node_id).trim();
    if (!id) continue;
    const metadata = asRecord(obj?.metadata) ?? {};
    const nodeType = normalizeNodeType(toString(obj?.node_type), id);
    const label = buildNodeLabel(id, nodeType, obj ?? {}, metadata);
    const shortLabel = label.length > 24 ? `${label.slice(0, 24)}...` : label;
    const kind = toString(obj?.kind ?? metadata.kind);
    const hash = toString(obj?.hash ?? metadata.hash);
    const entityId =
      toString(obj?.entity_id ?? metadata.entity_id) || (id.startsWith("endpoint:") ? id.slice(9) : "");
    const clusterKey = buildClusterKey(nodeType, obj ?? {}, metadata, kind);
    const clusterLabel = buildClusterLabel(nodeType, clusterKey, kind);
    const searchableText = [
      id,
      label,
      shortLabel,
      nodeType,
      kind,
      hash,
      entityId,
      objectText(metadata),
    ]
      .join(" ")
      .toLowerCase();

    baseNodes.push({
      id,
      label,
      shortLabel,
      nodeType,
      districtKey: normalizeDistrictKey(nodeType),
      clusterKey,
      clusterLabel,
      searchableText,
      metadata,
      kind,
      hash,
      entityId,
    });
  }

  const nodeByIdBase = new Map(baseNodes.map((node) => [node.id, node]));
  const edges: ParsedGraphEdge[] = [];

  for (const row of edgesRaw) {
    const obj = asRecord(row);
    const source = toString(obj?.source ?? obj?.from_node_id).trim();
    const target = toString(obj?.target ?? obj?.to_node_id).trim();
    if (!source || !target || !nodeByIdBase.has(source) || !nodeByIdBase.has(target)) continue;
    const edgeType = normalizeEdgeType(toString(obj?.edge_type));
    edges.push({
      id: toString(obj?.id ?? obj?.edge_id).trim() || `${edgeType}:${source}->${target}`,
      source,
      target,
      edgeType,
      weight: clamp(toNumber(obj?.weight, 1), 0.05, 10),
      count: Math.max(1, Math.round(toNumber(obj?.count, 1))),
      firstSeenMs: nullableNumber(obj?.first_seen_ms),
      lastSeenMs: nullableNumber(obj?.last_seen_ms),
      metadata: asRecord(obj?.metadata) ?? {},
    });
  }

  const outgoing = new Map<string, ParsedGraphEdge[]>();
  const incoming = new Map<string, ParsedGraphEdge[]>();
  const undirected = new Map<string, ParsedGraphEdge[]>();

  for (const edge of edges) {
    pushMapArray(outgoing, edge.source, edge);
    pushMapArray(incoming, edge.target, edge);
    pushMapArray(undirected, edge.source, edge);
    pushMapArray(undirected, edge.target, edge);
  }

  const nodes: ParsedGraphNode[] = baseNodes.map((node) => {
    const outDegree = (outgoing.get(node.id) ?? []).length;
    const inDegree = (incoming.get(node.id) ?? []).length;
    const degree = outDegree + inDegree;
    return {
      ...node,
      degree,
      inDegree,
      outDegree,
      importance: computeNodeImportance(node.nodeType, degree, inDegree, outDegree),
    };
  });

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const edgeById = new Map(edges.map((edge) => [edge.id, edge]));
  const edgeTypes = uniqueSorted(edges.map((edge) => edge.edgeType), (left, right) =>
    getEdgeMeta(left).label.localeCompare(getEdgeMeta(right).label),
  );
  const districtKeys = uniqueSorted(
    nodes.map((node) => node.districtKey),
    compareByStableMetaOrder(getDistrictMeta),
  );

  return {
    kind: "ok",
    graph: {
      version: Math.trunc(version),
      createdAtMs: Math.trunc(createdAtMs),
      nodes,
      edges,
      nodeById,
      edgeById,
      edgeTypes,
      districtKeys,
      outgoing,
      incoming,
      undirected,
    },
  };
}

export function buildDeterministicLayout(
  graph: ParsedGraph,
  options: {
    width: number;
    height: number;
    enabledEdgeTypes: Set<string>;
    pinnedNodeIds?: string[];
  },
): GraphRenderModel {
  const pinnedNodeIds = new Set((options.pinnedNodeIds ?? []).filter(Boolean));
  const filteredEdges = graph.edges.filter((edge) => options.enabledEdgeTypes.has(edge.edgeType));
  const nodesByDistrict = groupBy(
    graph.nodes,
    (node) => node.districtKey,
    compareByStableMetaOrder(getDistrictMeta),
  );
  const districtBudgets = allocateDistrictBudgets(nodesByDistrict, MAX_RENDER_NODES);
  const rawToDisplayNodeId = new Map<string, string>();
  const displayNodes: DisplayNode[] = [];
  const districtStats: Array<{
    key: string;
    totalNodes: number;
    hiddenNodes: number;
    clusterCount: number;
  }> = [];

  for (const [districtKey, districtNodes] of nodesByDistrict) {
    const budget = districtBudgets.get(districtKey) ?? districtNodes.length;
    const sortedNodes = [...districtNodes].sort(compareNodesForDisplay);
    const pinnedInDistrict = sortedNodes.filter((node) => pinnedNodeIds.has(node.id));
    let rawBudget = Math.min(sortedNodes.length, budget);
    let aggregateBudget = 0;

    if (sortedNodes.length > budget) {
      aggregateBudget = budget >= 8 ? 2 : 1;
      rawBudget = Math.max(2, budget - aggregateBudget);
      if (pinnedInDistrict.length > rawBudget) {
        rawBudget = Math.min(sortedNodes.length, pinnedInDistrict.length);
        aggregateBudget = Math.max(0, budget - rawBudget);
      }
    }

    const visibleRaw = new Set<string>(pinnedInDistrict.slice(0, rawBudget).map((node) => node.id));
    for (const node of sortedNodes) {
      if (visibleRaw.size >= rawBudget) break;
      visibleRaw.add(node.id);
    }

    const hiddenNodes = sortedNodes.filter((node) => !visibleRaw.has(node.id));
    const clusterGroups = groupBy(hiddenNodes, (node) => node.clusterKey);
    const aggregateGroups = collapseClusterGroups(clusterGroups, aggregateBudget);

    for (const node of sortedNodes) {
      if (!visibleRaw.has(node.id)) continue;
      rawToDisplayNodeId.set(node.id, node.id);
      displayNodes.push({
        id: node.id,
        label: node.label,
        shortLabel: node.shortLabel,
        nodeType: node.nodeType,
        districtKey,
        clusterKey: node.clusterKey,
        clusterLabel: node.clusterLabel,
        color: getDistrictMeta(districtKey).color,
        metadata: node.metadata,
        importance: node.importance,
        degree: node.degree,
        inDegree: node.inDegree,
        outDegree: node.outDegree,
        aggregate: false,
        hiddenCount: 0,
        memberNodeIds: [node.id],
        x: 0,
        y: 0,
        width: 0,
        height: 0,
      });
    }

    aggregateGroups.forEach((group, index) => {
      const aggregateId = `agg:${districtKey}:${index}`;
      const label = `${group.label} +${group.nodes.length}`;
      const importance =
        group.nodes.reduce((total, node) => total + node.importance, 0) / Math.max(1, group.nodes.length);
      const degree = group.nodes.reduce((total, node) => total + node.degree, 0);
      displayNodes.push({
        id: aggregateId,
        label,
        shortLabel: label.length > 24 ? `${label.slice(0, 24)}...` : label,
        nodeType: districtKey,
        districtKey,
        clusterKey: group.key,
        clusterLabel: group.label,
        color: getDistrictMeta(districtKey).color,
        metadata: { aggregate: true, label: group.label },
        importance,
        degree,
        inDegree: degree,
        outDegree: degree,
        aggregate: true,
        hiddenCount: group.nodes.length,
        memberNodeIds: group.nodes.map((node) => node.id),
        x: 0,
        y: 0,
        width: 0,
        height: 0,
      });
      group.nodes.forEach((node) => rawToDisplayNodeId.set(node.id, aggregateId));
    });

    districtStats.push({
      key: districtKey,
      totalNodes: sortedNodes.length,
      hiddenNodes: hiddenNodes.length,
      clusterCount: new Set(sortedNodes.map((node) => node.clusterKey)).size,
    });
  }

  const displayNodeLookup = new Map(displayNodes.map((node) => [node.id, node]));
  const displayEdgeMap = new Map<string, DisplayEdge>();
  for (const edge of filteredEdges) {
    const source = rawToDisplayNodeId.get(edge.source);
    const target = rawToDisplayNodeId.get(edge.target);
    if (!source || !target || source === target) continue;
    const sourceDistrict = displayNodeLookup.get(source)?.districtKey ?? "other";
    const targetDistrict = displayNodeLookup.get(target)?.districtKey ?? "other";
    const key = `${source}:${target}:${edge.edgeType}`;
    const existing = displayEdgeMap.get(key);
    if (existing) {
      existing.count += edge.count;
      existing.weight = Math.max(existing.weight, edge.weight);
      existing.memberEdgeIds.push(edge.id);
      existing.firstSeenMs = pickMin(existing.firstSeenMs, edge.firstSeenMs);
      existing.lastSeenMs = pickMax(existing.lastSeenMs, edge.lastSeenMs);
      continue;
    }
    const meta = getEdgeMeta(edge.edgeType);
    displayEdgeMap.set(key, {
      id: key,
      source,
      target,
      edgeType: edge.edgeType,
      count: edge.count,
      weight: edge.weight,
      firstSeenMs: edge.firstSeenMs,
      lastSeenMs: edge.lastSeenMs,
      color: meta.color,
      dashArray: meta.dashArray,
      aggregate: source.startsWith("agg:") || target.startsWith("agg:"),
      memberEdgeIds: [edge.id],
      sourceDistrict,
      targetDistrict,
      metadata: edge.metadata,
    });
  }

  const edges = [...displayEdgeMap.values()]
    .sort((left, right) => {
      const scoreLeft = left.count * 10 + left.weight;
      const scoreRight = right.count * 10 + right.weight;
      if (scoreRight !== scoreLeft) return scoreRight - scoreLeft;
      return left.id.localeCompare(right.id);
    })
    .slice(0, MAX_RENDER_EDGES);

  const frames = arrangeDistrictFrames(
    districtStats.map((district) => district.key),
    options.width,
    options.height,
  );
  const frameByDistrict = new Map(frames.map((frame) => [frame.key, frame]));
  const displayNodeGroups = groupBy(
    displayNodes,
    (node) => node.districtKey,
    compareByStableMetaOrder(getDistrictMeta),
  );
  const positionedNodes: DisplayNode[] = [];

  for (const [districtKey, group] of displayNodeGroups) {
    const frame = frameByDistrict.get(districtKey);
    if (!frame) continue;
    positionedNodes.push(...positionDistrictNodes(group, frame));
  }

  const nodeById = new Map(positionedNodes.map((node) => [node.id, node]));
  const districts: DisplayDistrict[] = districtStats
    .map((district) => {
      const frame = frameByDistrict.get(district.key);
      if (!frame) return null;
      return {
        key: district.key,
        label: getDistrictMeta(district.key).label,
        color: getDistrictMeta(district.key).color,
        nodeType: district.key,
        totalNodes: district.totalNodes,
        hiddenNodes: district.hiddenNodes,
        clusterCount: district.clusterCount,
        x: frame.x,
        y: frame.y,
        w: frame.w,
        h: frame.h,
        nodeIds: positionedNodes.filter((node) => node.districtKey === district.key).map((node) => node.id),
      };
    })
    .filter((district): district is DisplayDistrict => district !== null)
    .sort(compareDistricts);

  const edgeById = new Map(edges.map((edge) => [edge.id, edge]));
  const districtLinks = buildDistrictLinks(edges);

  return {
    nodes: positionedNodes.sort(compareDisplayNodes),
    edges,
    districts,
    districtLinks,
    nodeById,
    edgeById,
    rawToDisplayNodeId,
  };
}

export function collectFocusNeighborhood(
  graph: ParsedGraph,
  anchorNodeId: string,
  depth: number,
  enabledEdgeTypes: Set<string>,
) {
  const nodeIds = new Set<string>();
  const edgeIds = new Set<string>();
  if (!anchorNodeId || !graph.nodeById.has(anchorNodeId)) {
    return { nodeIds, edgeIds };
  }

  const queue: Array<{ id: string; depth: number }> = [{ id: anchorNodeId, depth: 0 }];
  nodeIds.add(anchorNodeId);

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || current.depth >= depth) continue;
    const neighbors = graph.undirected.get(current.id) ?? [];
    for (const edge of neighbors) {
      if (!enabledEdgeTypes.has(edge.edgeType)) continue;
      edgeIds.add(edge.id);
      const nextId = edge.source === current.id ? edge.target : edge.source;
      if (nodeIds.has(nextId)) continue;
      nodeIds.add(nextId);
      queue.push({ id: nextId, depth: current.depth + 1 });
    }
  }

  return { nodeIds, edgeIds };
}

export function findRoute(
  graph: ParsedGraph,
  startNodeId: string,
  endNodeId: string,
  enabledEdgeTypes: Set<string>,
) {
  if (!startNodeId || !endNodeId || !graph.nodeById.has(startNodeId) || !graph.nodeById.has(endNodeId)) {
    return null;
  }
  if (startNodeId === endNodeId) {
    return { nodeIds: [startNodeId], edgeIds: [] as string[] };
  }

  const queue = [startNodeId];
  const parents = new Map<string, { nodeId: string; edgeId: string }>();
  const visited = new Set([startNodeId]);

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    const neighbors = graph.undirected.get(current) ?? [];
    for (const edge of neighbors) {
      if (!enabledEdgeTypes.has(edge.edgeType)) continue;
      const nextId = edge.source === current ? edge.target : edge.source;
      if (visited.has(nextId)) continue;
      visited.add(nextId);
      parents.set(nextId, { nodeId: current, edgeId: edge.id });
      if (nextId === endNodeId) {
        const nodeIds: string[] = [endNodeId];
        const edgeIds: string[] = [];
        let cursor = endNodeId;
        while (cursor !== startNodeId) {
          const parent = parents.get(cursor);
          if (!parent) break;
          edgeIds.push(parent.edgeId);
          cursor = parent.nodeId;
          nodeIds.push(cursor);
        }
        nodeIds.reverse();
        edgeIds.reverse();
        return { nodeIds, edgeIds };
      }
      queue.push(nextId);
    }
  }

  return null;
}

export function getRepresentativeRawNodeId(displayNode: DisplayNode | undefined): string {
  if (!displayNode) return "";
  return displayNode.memberNodeIds[0] ?? "";
}

function normalizeNodeType(value: string, nodeId: string) {
  if (value) return value.trim().toLowerCase();
  if (nodeId.startsWith("endpoint:")) return "endpoint";
  if (nodeId.startsWith("evidence::")) return "evidence";
  if (nodeId.startsWith("identity:")) return "identity";
  if (nodeId.startsWith("trust:")) return "trust_material";
  if (nodeId.startsWith("session:")) return "session";
  return "other";
}

function normalizeDistrictKey(nodeType: string) {
  if (nodeType in DISTRICT_META) return nodeType;
  if (nodeType.includes("trust")) return "trust_material";
  if (nodeType.includes("identity")) return "identity";
  if (nodeType.includes("evidence")) return "evidence";
  if (nodeType.includes("endpoint")) return "endpoint";
  if (nodeType.includes("session")) return "session";
  return "other";
}

function normalizeEdgeType(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized || "other";
}

function buildNodeLabel(
  id: string,
  nodeType: string,
  node: Record<string, unknown>,
  metadata: Record<string, unknown>,
) {
  const explicit = toString(node.label);
  if (explicit) return explicit;
  if (nodeType === "endpoint") {
    return (
      toString(node.hostname ?? metadata.hostname) ||
      toString(node.entity_id ?? metadata.entity_id) ||
      id.replace(/^endpoint:/, "")
    );
  }
  if (nodeType === "evidence") {
    const kind = toString(node.kind ?? metadata.kind) || "evidence";
    const fingerprint = toString(node.fingerprint_id ?? metadata.fingerprint_id);
    return fingerprint ? `${kind} ${fingerprint}` : kind;
  }
  if (nodeType === "identity") {
    const kind = toString(node.kind ?? metadata.kind) || "identity";
    const hash = shortHash(toString(node.hash ?? metadata.hash), 10);
    return hash ? `${kind} ${hash}` : kind;
  }
  if (nodeType === "trust_material") {
    const kind = toString(node.kind ?? metadata.kind) || "trust";
    const hash = shortHash(toString(node.hash ?? metadata.hash), 10);
    return hash ? `${kind} ${hash}` : kind;
  }
  if (nodeType === "session") {
    return toString(node.session_key ?? metadata.session_key) || "session";
  }
  return id;
}

function buildClusterKey(
  nodeType: string,
  node: Record<string, unknown>,
  metadata: Record<string, unknown>,
  kind: string,
) {
  if (nodeType === "endpoint") {
    const port = toString(node.port ?? metadata.port);
    return port ? `port:${port}` : "port:unknown";
  }
  if (nodeType === "evidence" || nodeType === "identity" || nodeType === "trust_material") {
    return kind || `${nodeType}:default`;
  }
  if (nodeType === "session") {
    return toString(node.entity_id ?? metadata.entity_id) || "session:default";
  }
  return nodeType;
}

function buildClusterLabel(nodeType: string, clusterKey: string, kind: string) {
  if (nodeType === "endpoint") {
    return clusterKey.replace("port:", "Port ");
  }
  if (kind) return humanize(kind);
  return humanize(clusterKey);
}

function computeNodeImportance(nodeType: string, degree: number, inDegree: number, outDegree: number) {
  const base =
    nodeType === "endpoint"
      ? 8
      : nodeType === "identity"
        ? 6
        : nodeType === "trust_material"
          ? 5
          : nodeType === "session"
            ? 4
            : nodeType === "evidence"
              ? 3
              : 2;
  return base + degree * 1.35 + outDegree * 0.4 + inDegree * 0.2;
}

function allocateDistrictBudgets(
  districts: Map<string, ParsedGraphNode[]>,
  maxTotal: number,
) {
  const budgets = new Map<string, number>();
  const totalNodes = [...districts.values()].reduce((total, nodes) => total + nodes.length, 0);
  if (totalNodes <= maxTotal) {
    for (const [key, nodes] of districts) budgets.set(key, nodes.length);
    return budgets;
  }

  const entries = [...districts.entries()];
  let remaining = maxTotal;
  const extraMeta: Array<{ key: string; remainingCapacity: number; remainder: number }> = [];

  for (const [key, nodes] of entries) {
    const base = Math.min(nodes.length, Math.min(4, nodes.length));
    budgets.set(key, base);
    remaining -= base;
  }

  const extraCapacity = entries.reduce(
    (total, [key, nodes]) => total + Math.max(0, nodes.length - (budgets.get(key) ?? 0)),
    0,
  );

  for (const [key, nodes] of entries) {
    const base = budgets.get(key) ?? 0;
    const capacity = Math.max(0, nodes.length - base);
    if (!capacity || remaining <= 0 || !extraCapacity) {
      extraMeta.push({ key, remainingCapacity: capacity, remainder: 0 });
      continue;
    }
    const exact = (remaining * capacity) / extraCapacity;
    const whole = Math.min(capacity, Math.floor(exact));
    budgets.set(key, base + whole);
    extraMeta.push({ key, remainingCapacity: capacity - whole, remainder: exact - whole });
  }

  let used = [...budgets.values()].reduce((total, value) => total + value, 0);
  extraMeta.sort((left, right) => {
    if (right.remainder !== left.remainder) return right.remainder - left.remainder;
    return compareDistrictsByKey(left.key, right.key);
  });
  for (const entry of extraMeta) {
    if (used >= maxTotal) break;
    if (entry.remainingCapacity <= 0) continue;
    budgets.set(entry.key, (budgets.get(entry.key) ?? 0) + 1);
    used += 1;
  }

  return budgets;
}

function collapseClusterGroups(groups: Map<string, ParsedGraphNode[]>, maxGroups: number) {
  const ordered = [...groups.entries()]
    .map(([key, nodes]) => ({
      key,
      nodes,
      label: nodes[0]?.clusterLabel || humanize(key),
      score: nodes.reduce((total, node) => total + node.importance, 0),
    }))
    .sort((left, right) => {
      if (right.nodes.length !== left.nodes.length) return right.nodes.length - left.nodes.length;
      if (right.score !== left.score) return right.score - left.score;
      return left.key.localeCompare(right.key);
    });

  if (maxGroups <= 0 || ordered.length === 0) return [];
  if (ordered.length <= maxGroups) {
    return ordered.map((group) => ({ ...group, kind: "cluster" as const }));
  }
  if (maxGroups === 1) {
    return [
      {
        key: "overflow",
        label: "Other links",
        nodes: ordered.flatMap((group) => group.nodes),
        score: ordered.reduce((total, group) => total + group.score, 0),
        kind: "overflow" as const,
      },
    ];
  }

  const keep: Array<{
    key: string;
    nodes: ParsedGraphNode[];
    label: string;
    score: number;
    kind: "cluster" | "overflow";
  }> = ordered.slice(0, maxGroups - 1).map((group) => ({ ...group, kind: "cluster" as const }));
  const overflow = ordered.slice(maxGroups - 1);
  keep.push({
    key: "overflow",
    label: "Other links",
    nodes: overflow.flatMap((group) => group.nodes),
    score: overflow.reduce((total, group) => total + group.score, 0),
    kind: "overflow" as const,
  });
  return keep;
}

function arrangeDistrictFrames(districtKeys: string[], width: number, height: number) {
  const orderedKeys = [...districtKeys].sort(compareDistrictsByKey);
  const gutter = 18;
  const top = 46;
  const left = 12;
  const usableWidth = width - left * 2;
  const usableHeight = height - top - 18;
  if (orderedKeys.length === 1) {
    return [{ key: orderedKeys[0], x: left, y: top, w: usableWidth, h: usableHeight }];
  }
  if (orderedKeys.length === 2) {
    const colWidth = (usableWidth - gutter) / 2;
    return [
      { key: orderedKeys[0], x: left, y: top, w: colWidth, h: usableHeight },
      { key: orderedKeys[1], x: left + colWidth + gutter, y: top, w: colWidth, h: usableHeight },
    ];
  }

  const columns = 2;
  const rows = Math.ceil(orderedKeys.length / columns);
  const colWidth = (usableWidth - gutter) / columns;
  const rowHeight = (usableHeight - gutter * (rows - 1)) / rows;
  return orderedKeys.map((key, index) => {
    const row = Math.floor(index / columns);
    const col = index % columns;
    return {
      key,
      x: left + col * (colWidth + gutter),
      y: top + row * (rowHeight + gutter),
      w: colWidth,
      h: rowHeight,
    };
  });
}

function positionDistrictNodes(nodes: DisplayNode[], frame: DistrictFrame) {
  const sorted = [...nodes].sort(compareDisplayNodes);
  const grouped = groupBy(sorted, (node) => node.clusterKey);
  const clusterEntries = [...grouped.entries()].sort((left, right) => {
    const scoreLeft = left[1].reduce((total, node) => total + node.importance, 0);
    const scoreRight = right[1].reduce((total, node) => total + node.importance, 0);
    if (scoreRight !== scoreLeft) return scoreRight - scoreLeft;
    return left[0].localeCompare(right[0]);
  });

  const centerX = frame.x + frame.w / 2;
  const centerY = frame.y + frame.h / 2 + 8;
  const ringRadiusX = Math.max(0, frame.w * 0.22);
  const ringRadiusY = Math.max(0, frame.h * 0.18);
  const positioned: DisplayNode[] = [];

  clusterEntries.forEach(([clusterKey, clusterNodes], clusterIndex) => {
    const clusterSeed = stableHash(`${frame.key}:${clusterKey}`);
    const random = seededRandom(clusterSeed);
    const clusterCount = clusterEntries.length;
    const angleBase =
      clusterCount === 1
        ? -Math.PI / 2
        : -Math.PI / 2 + (Math.PI * 2 * clusterIndex) / clusterCount + (random() - 0.5) * 0.18;
    const clusterX = centerX + (clusterCount === 1 ? 0 : Math.cos(angleBase) * ringRadiusX);
    const clusterY = centerY + (clusterCount === 1 ? 0 : Math.sin(angleBase) * ringRadiusY);
    clusterNodes.sort(compareDisplayNodes);

    clusterNodes.forEach((node, nodeIndex) => {
      const { width, height } = computeBuildingSize(node);
      let x = clusterX;
      let y = clusterY;
      if (nodeIndex > 0) {
        const ring = Math.floor((nodeIndex - 1) / 6) + 1;
        const slot = (nodeIndex - 1) % 6;
        const slotCount = ring * 6;
        const angle = angleBase + (Math.PI * 2 * slot) / slotCount + (random() - 0.5) * 0.1;
        const radius = 28 + ring * 24;
        x = clusterX + Math.cos(angle) * radius;
        y = clusterY + Math.sin(angle) * radius;
      }
      positioned.push({
        ...node,
        width,
        height,
        x: clamp(x, frame.x + width / 2 + 12, frame.x + frame.w - width / 2 - 12),
        y: clamp(y, frame.y + 36 + height / 2, frame.y + frame.h - height / 2 - 12),
      });
    });
  });

  return positioned;
}

function computeBuildingSize(node: DisplayNode) {
  const labelWidth = clamp(node.label.length * 4.4, 34, 96);
  if (node.aggregate) {
    return {
      width: clamp(labelWidth + node.hiddenCount * 2.4, 56, 118),
      height: clamp(26 + node.hiddenCount * 0.35, 28, 40),
    };
  }
  return {
    width: clamp(labelWidth + node.importance * 1.5, 38, 110),
    height: clamp(22 + node.importance * 0.45, 22, 38),
  };
}

function buildDistrictLinks(edges: DisplayEdge[]) {
  const links = new Map<string, DistrictLink>();
  for (const edge of edges) {
    if (edge.sourceDistrict === edge.targetDistrict) continue;
    const key = [edge.sourceDistrict, edge.targetDistrict].sort(compareDistrictsByKey).join("::");
    const existing = links.get(key);
    if (existing) {
      existing.count += edge.count;
      existing.weight = Math.max(existing.weight, edge.weight);
      if (!existing.edgeTypes.includes(edge.edgeType)) existing.edgeTypes.push(edge.edgeType);
      continue;
    }
    links.set(key, {
      id: key,
      sourceDistrict: edge.sourceDistrict,
      targetDistrict: edge.targetDistrict,
      count: edge.count,
      weight: edge.weight,
      edgeTypes: [edge.edgeType],
    });
  }
  return [...links.values()].sort((left, right) => right.count - left.count);
}

function compareNodesForDisplay(left: ParsedGraphNode, right: ParsedGraphNode) {
  if (right.importance !== left.importance) return right.importance - left.importance;
  if (right.degree !== left.degree) return right.degree - left.degree;
  return left.id.localeCompare(right.id);
}

function compareDisplayNodes(left: DisplayNode, right: DisplayNode) {
  if (left.aggregate !== right.aggregate) return left.aggregate ? 1 : -1;
  if (right.importance !== left.importance) return right.importance - left.importance;
  return left.id.localeCompare(right.id);
}

function compareDistricts(left: DisplayDistrict, right: DisplayDistrict) {
  return compareDistrictsByKey(left.key, right.key);
}

function compareDistrictsByKey(left: string, right: string) {
  const leftOrder = getDistrictMeta(left).order;
  const rightOrder = getDistrictMeta(right).order;
  if (leftOrder !== rightOrder) return leftOrder - rightOrder;
  return left.localeCompare(right);
}

function compareByStableMetaOrder<T extends { order: number }>(getter: (key: string) => T) {
  return (left: string, right: string) => {
    const leftMeta = getter(left);
    const rightMeta = getter(right);
    if (leftMeta.order !== rightMeta.order) return leftMeta.order - rightMeta.order;
    return left.localeCompare(right);
  };
}

function shortHash(value: string, length: number) {
  if (!value) return "";
  return value.length > length ? `${value.slice(0, length)}...` : value;
}

function humanize(value: string) {
  return value
    .replace(/[_:]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function objectText(value: Record<string, unknown>) {
  return Object.entries(value)
    .map(([key, entry]) => `${key}:${toString(entry)}`)
    .join(" ");
}

function uniqueSorted(values: string[], compare: (left: string, right: string) => number) {
  return [...new Set(values.filter(Boolean))].sort(compare);
}

function groupBy<T>(
  values: T[],
  keyGetter: (value: T) => string,
  sortComparator?: (left: string, right: string) => number,
) {
  const grouped = new Map<string, T[]>();
  for (const value of values) {
    const key = keyGetter(value);
    const existing = grouped.get(key);
    if (existing) existing.push(value);
    else grouped.set(key, [value]);
  }
  if (!sortComparator) return grouped;
  return new Map([...grouped.entries()].sort((left, right) => sortComparator(left[0], right[0])));
}

function pickMin(left: number | null, right: number | null) {
  if (left == null) return right;
  if (right == null) return left;
  return Math.min(left, right);
}

function pickMax(left: number | null, right: number | null) {
  if (left == null) return right;
  if (right == null) return left;
  return Math.max(left, right);
}

function stableHash(input: string) {
  let hash = 2166136261;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function pushMapArray<T>(map: Map<string, T[]>, key: string, value: T) {
  const existing = map.get(key);
  if (existing) existing.push(value);
  else map.set(key, [value]);
}

function clamp(value: number, min: number, max: number) {
  return value < min ? min : value > max ? max : value;
}

function asRecord(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  return input as Record<string, unknown>;
}

function toString(value: unknown) {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function toNumber(value: unknown, fallback = 0) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function nullableNumber(value: unknown) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}
