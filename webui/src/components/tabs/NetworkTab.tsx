// ═══════════════════════════════════════════════════
// Network Tab - Interactive network topology dashboard
// Performance-optimized for 200+ nodes via:
//   - Node pagination (top-N by count)
//   - Edge filtering (top-N by weight, prevents O(N²))
//   - Non-mutating hover highlight (nodeColor callback)
//   - Adaptive simulation params (cooldownTicks, link force)
//   - Canvas draw optimization (skip glow/labels for high counts)
// ═══════════════════════════════════════════════════

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import ForceGraph2D from 'react-force-graph-2d';
import { forceLink } from 'd3-force';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { TabQueryWrapper } from '../../components/TabQueryWrapper';
import {
  Network, Activity, Globe, Shield, Server, Wifi, Radio,
  ArrowUpRight, ArrowDownRight, Eye, MousePointer2,
  Maximize2, Minimize2
} from 'lucide-react';

// ── Color Scheme ──
const COLORS = {
  LAN: '#00ff88', WAN: '#ff006e', VPN: '#8338ec', DMZ: '#ffbe0b', UNKNOWN: '#64748b',
};

// ── Stat Card Component ──
function StatCard({ title, value, subtitle, icon, color, trend }: {
  title: string; value: string | number; subtitle?: string;
  icon: React.ReactNode; color: string; trend?: { value: number; positive: boolean };
}) {
  return (
    <div className="cyber-card p-4 cyber-card-hover group">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-md" style={{ background: `${color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {icon}
          </div>
          <span className="cyber-stat-label">{title}</span>
        </div>
        {trend && (
          <span className={`flex items-center gap-0.5 text-xs font-mono ${trend.positive ? 'text-cyber-green' : 'text-cyber-red'}`}>
            {trend.positive ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
            {trend.value}%
          </span>
        )}
      </div>
      <div className="text-2xl font-bold font-mono" style={{ color }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {subtitle && <div className="text-xs text-cyber-textMuted mt-1">{subtitle}</div>}
    </div>
  );
}

// ── Force Graph Component (performance-optimized) ──
function NetworkGraph({ nodes, edges, maxNodes, activeCategories, totalNodeCount, totalEdgeCount }: {
  nodes: any[]; edges: any[]; maxNodes?: number; activeCategories?: Set<string>; totalNodeCount?: number; totalEdgeCount?: number;
}) {
  const graphRef = useRef<any>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [connectedIds, setConnectedIds] = useState<Set<string>>(new Set());
  const [zoom, setZoom] = useState(1);

  // Sort nodes by count desc so top nodes always appear when paginated
  const sortedNodes = useMemo(() => {
    return [...nodes].sort((a, b) => (b.count || 0) - (a.count || 0));
  }, [nodes]);

  // Apply category filter + pagination (top-N by count)
  const filteredNodes = useMemo(() => {
    let result = sortedNodes;
    if (activeCategories && activeCategories.size > 0) {
      result = result.filter(n => activeCategories.has(n.category));
    }
    const limit = maxNodes ?? result.length;
    return result.slice(0, limit);
  }, [sortedNodes, maxNodes, activeCategories]);

  // Prepare graph data with EDGE FILTERING (top-N by weight)
  const graphData = useMemo(() => {
    const nodeMap = new Map<string, any>();

    // Add visible nodes
    filteredNodes.forEach(node => {
      const id = node.id || node.label;
      nodeMap.set(id, {
        id,
        label: node.label || id,
        size: Math.max(6, Math.min(20, (node.count || 0) / 50)),
        color: COLORS[node.category] || '#64748b',
        category: node.category,
        count: node.count || 0,
      });
    });

    // Filter edges: only between visible nodes
    const visibleEdges = edges.filter(edge =>
      nodeMap.has(edge.source) && nodeMap.has(edge.target)
    );

    // Edge pagination: sort by weight, keep top-N
    // This prevents O(N²) edge explosion with hundreds of nodes
    const nodeCount = nodeMap.size;
    const maxEdges = nodeCount > 200 ? 500 : nodeCount > 100 ? 300 : visibleEdges.length;
    const sortedEdges = [...visibleEdges].sort((a, b) => (b.value || 0) - (a.value || 0));
    const paginatedEdges = sortedEdges.slice(0, maxEdges);

    const graphEdges = paginatedEdges.map(edge => ({
      source: edge.source,
      target: edge.target,
      weight: edge.value || 1,
      color: COLORS[edge.source?.category || 'UNKNOWN'],
    }));

    return { nodes: Array.from(nodeMap.values()), links: graphEdges, edgeCount: graphEdges.length };
  }, [filteredNodes, edges]);

  // Adaptive simulation params based on node count
  const nodeCount = graphData.nodes.length;
  const linkCount = graphData.edgeCount;
  // Aggressive cooldown reduction for large graphs:
  // 200+ nodes -> 20 ticks (quick initial layout only)
  // 100-200 nodes -> 50 ticks
  // <100 nodes -> 150 ticks (full simulation)
  const cooldownTicks = nodeCount > 200 ? 20 : nodeCount > 100 ? 50 : 150;
  const linkDistance = Math.max(20, Math.min(60, 3000 / Math.max(nodeCount, 10)));

  const getLinkColor = (link: any) => {
    const baseColor = link.color || '#64748b';
    return baseColor + '40';
  };

  // Node color callback for hover highlighting (no mutation!)
  // Replaces the old onNodeHover mutation pattern which triggered simulation recalc
  const getNodeColor = useCallback((node: any) => {
    if (!hoveredNodeId) {
      return node.color || '#64748b';
    }
    // Dim unconnected nodes, keep connected nodes bright
    const isConnected = connectedIds.has(node.id);
    const baseColor = node.color || '#64748b';
    // Apply opacity via hex alpha channel (no re-render since node object unchanged)
    return isConnected ? baseColor : baseColor + '25';
  }, [hoveredNodeId, connectedIds]);

  // Optimized canvas draw: skip expensive ops for high node counts
  const getNodeCanvasObjectDraw = useCallback((node: any, ctx: any, globalScale: number) => {
    const nodeColor = node.color || '#64748b';
    const isDimmed = hoveredNodeId && !connectedIds.has(node.id);

    // Glow: only for larger nodes AND when not too many nodes (expensive!)
    if (node.size >= 10 && nodeCount <= 100 && !isDimmed) {
      ctx.shadowColor = nodeColor;
      ctx.shadowBlur = 8;
    } else {
      ctx.shadowBlur = 0;
    }

    ctx.beginPath();
    ctx.arc(node.x || 0, node.y || 0, node.size, 0, 2 * Math.PI);

    // Fill with alpha for dimming (canvas-level, no state mutation)
    if (isDimmed) {
      ctx.fillStyle = nodeColor + '25';
    } else {
      ctx.fillStyle = nodeColor + '80';
    }
    ctx.fill();
    ctx.shadowBlur = 0;

    // Label threshold: only draw labels for larger nodes OR when zoomed in > 2x
    // Skip labels entirely when node count is high (performance)
    const maxNodesForLabels = nodeCount > 150 ? 12 : nodeCount > 80 ? 8 : 6;
    const showLabel = node.size >= maxNodesForLabels || globalScale > 2;
    if (showLabel && !isDimmed) {
      const label = node.label || node.id;
      const fontSize = 8;
      ctx.font = `${fontSize}px monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText(label, node.x || 0, (node.y || 0) - node.size - 4);
    }
  }, [hoveredNodeId, connectedIds, nodeCount]);

  // Hover handler: compute connected IDs without mutating graph data
  const handleNodeHover = useCallback((node: any) => {
    if (node) {
      setHoveredNodeId(node.id);
      const connected = new Set<string>();
      connected.add(node.id);
      graphData.links.forEach((link: any) => {
        if (link.source.id === node.id) connected.add(link.target.id);
        if (link.target.id === node.id) connected.add(link.source.id);
      });
      setConnectedIds(connected);
    } else {
      setHoveredNodeId(null);
      setConnectedIds(new Set());
    }
  }, [graphData.links]);

  // Configure d3 force simulation params via instance methods
  // (linkDistance, linkStrength are NOT React props in react-force-graph-2d v1.29+)
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    // Create a properly configured link force instance
    const linkStrengthVal = nodeCount > 100 ? 0.2 : 0.5;
    fg.d3Force('link', forceLink().distance(linkDistance).strength(linkStrengthVal));
  }, [nodeCount, linkDistance]);

  // Find hovered node data for tooltip
  const hoveredNodeData = hoveredNodeId ? graphData.nodes.find((n: any) => n.id === hoveredNodeId) : null;

  const visibleCount = graphData.nodes.length;

  return (
    <div className="relative">
      {/* Graph Controls */}
      <div className="absolute top-2 right-2 z-10 flex gap-2">
        <button
          onClick={() => { graphRef.current?.zoomIn(); setZoom(z => z * 1.2); }}
          className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
          title="Zoom In"
        >
          <Maximize2 size={12} />
        </button>
        <button
          onClick={() => { graphRef.current?.zoomOut(); setZoom(z => z / 1.2); }}
          className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
          title="Zoom Out"
        >
          <Minimize2 size={12} />
        </button>
        <button
          onClick={() => { graphRef.current?.centerAt(600, 300).zoom(1); setZoom(1); }}
          className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
          title="Reset View"
        >
          <Eye size={12} />
        </button>
      </div>

      {/* Node + Edge Count Badge */}
      <div className="absolute top-2 left-2 z-10 flex items-center gap-2">
        <div className="cyber-card px-3 py-1.5 text-xs font-mono flex items-center gap-2">
          <span className="text-cyber-textMuted">{visibleCount} nodes</span>
          {totalNodeCount && totalNodeCount > visibleCount && (
            <>
              <span className="text-cyber-textMuted/50">/</span>
              <span className="text-cyber-textMuted/50">{totalNodeCount} total</span>
            </>
          )}
          <span className="text-cyber-textMuted/50">·</span>
          <span className="text-cyber-textMuted">{linkCount} edges</span>
          {totalEdgeCount && totalEdgeCount > linkCount && (
            <>
              <span className="text-cyber-textMuted/50">/</span>
              <span className="text-cyber-textMuted/50">{totalEdgeCount}</span>
            </>
          )}
          {nodeCount > 100 && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-accent/10 text-cyber-accent">optimized</span>
          )}
        </div>
      </div>

      {/* Hover Info */}
      {hoveredNodeData && (
        <div className="absolute bottom-2 left-2 z-10 cyber-card p-3 text-xs font-mono max-w-[280px]">
          <div className="font-semibold" style={{ color: hoveredNodeData.color }}>{hoveredNodeData.label}</div>
          <div className="text-cyber-textMuted">Category: {hoveredNodeData.category}</div>
          <div className="text-cyber-textMuted">Events: {(hoveredNodeData.count || 0).toLocaleString()}</div>
        </div>
      )}

      {/* Force Graph */}
      <div className="cyber-card p-4 scanlines" style={{ height: '150px' }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={{ nodes: graphData.nodes, links: graphData.links }}
          nodeLabel="label"
          nodeCanvasObject={getNodeCanvasObjectDraw}
          nodeColor={getNodeColor}
          linkColor={getLinkColor}
          linkWidth={(link: any) => Math.max(0.5, Math.min(3, (link.weight || 1) / 20))}
          linkDirectionalArrowLength={(link: any) => Math.max(4, (link.weight || 1) / 5)}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.15}
          onNodeHover={handleNodeHover}
          cooldownTicks={cooldownTicks}
          nodeRelSize={Math.max(4, Math.min(8, 800 / Math.max(nodeCount, 10)))}
          width={1200}
          height={450}
        />
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6 mt-3 px-4">
        {Object.entries(COLORS).map(([cat, color]) => (
          <div key={cat} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}60` }} />
            <span className="text-xs text-cyber-textMuted">{cat}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Traffic Distribution Chart ──
function TrafficDistribution({ stats }: { stats: any }) {
  const byType = stats?.by_type || {};
  const data = [
    { name: 'External', value: byType.external || 0, color: '#ff006e' },
    { name: 'Unknown', value: byType.unknown || 0, color: '#64748b' },
    { name: 'Internal', value: byType.internal || 0, color: '#00ff88' },
    { name: 'VPN', value: byType.vpn || 0, color: '#8338ec' },
  ].filter(d => d.value > 0);

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Globe size={14} /> Traffic Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: '#0d1117', border: '1px solid #1e293b', borderRadius: '8px', color: '#e2e8f0', fontFamily: 'monospace' }}
            formatter={(value: number) => value.toLocaleString()}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Interface Traffic Chart ──
function InterfaceTraffic({ stats }: { stats: any }) {
  const topSources = stats?.top_sources || [];
  // Filter out 0.0.0.0 entries which are aggregates
  const interfaces = topSources
    .filter((s: any) => s.interface && s.ip !== '0.0.0.0')
    .map((s: any) => ({
      name: s.interface,
      events: s.count,
      category: s.category,
      color: COLORS[s.category] || '#64748b',
    }))
    .sort((a, b) => b.events - a.events)
    .slice(0, 10);

  if (interfaces.length === 0) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <Server size={14} /> Interface Traffic
        </h3>
        <div className="text-center py-8 text-cyber-textMuted">No interface data available</div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Server size={14} /> Interface Traffic
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={interfaces} layout="vertical" margin={{ left: 0, right: 30 }}>
          <XAxis type="number" hide />
          <YAxis
            dataKey="name"
            type="category"
            width={100}
            tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }}
          />
          <Tooltip
            contentStyle={{ background: '#0d1117', border: '1px solid #1e293b', borderRadius: '8px', color: '#e2e8f0', fontFamily: 'monospace' }}
            formatter={(value: number) => value.toLocaleString()}
          />
          <Bar dataKey="events" radius={[0, 4, 4, 0]} barSize={16}>
            {interfaces.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Category Stats Chart ──
function CategoryStats({ stats }: { stats: any }) {
  const categories = stats?.categories || {};
  const data = Object.entries(categories).map(([name, value]) => ({
    name,
    count: value as number,
    color: COLORS[name] || '#64748b',
  }));

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Shield size={14} /> Category Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data}>
          <XAxis
            dataKey="name"
            tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }}
          />
          <YAxis tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'monospace' }} />
          <Tooltip
            contentStyle={{ background: '#0d1117', border: '1px solid #1e293b', borderRadius: '8px', color: '#e2e8f0', fontFamily: 'monospace' }}
            formatter={(value: number) => value.toLocaleString()}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} barSize={40}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.color}40)` }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Top Sources Table ──
function TopSourcesTable({ stats }: { stats: any }) {
  const topSources = stats?.top_sources || [];
  const sources = topSources.slice(0, 10);

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <MousePointer2 size={14} /> Top Sources
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead>
            <tr className="border-b border-cyber-border">
              <th className="text-left py-2 px-3 text-cyber-textMuted">IP</th>
              <th className="text-right py-2 px-3 text-cyber-textMuted">Events</th>
              <th className="text-left py-2 px-3 text-cyber-textMuted">Category</th>
              <th className="text-left py-2 px-3 text-cyber-textMuted">Interface</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((source: any, i: number) => (
              <tr key={i} className="border-b border-cyber-border/30 hover:bg-cyber-panelHover">
                <td className="py-2 px-3 text-cyber-text">
                  {source.ip || '0.0.0.0'}
                </td>
                <td className="py-2 px-3 text-right text-neon-cyan">
                  {(source.count || 0).toLocaleString()}
                </td>
                <td className="py-2 px-3">
                  <span
                    className="px-2 py-0.5 rounded text-xs"
                    style={{
                      background: `${COLORS[source.category] || '#64748b'}15`,
                      color: COLORS[source.category] || '#64748b',
                    }}
                  >
                    {source.category}
                  </span>
                </td>
                <td className="py-2 px-3 text-cyber-textMuted">
                  {source.interface || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Main NetworkTab Component ──
export default function NetworkTab() {
  const { data: flowData, isLoading: flowLoading, isError: flowError, error: flowErrorObj, refetch: refetchFlow } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  const { data: stats } = useQuery<any>({
    queryKey: ['stats'],
    queryFn: api.stats,
    refetchInterval: 30000,
  });

  // Pagination state
  const [maxNodes, setMaxNodes] = useState(50);
  const [activeCategories, setActiveCategories] = useState<Set<string>>(new Set());

  // Toggle category filter
  const toggleCategory = useCallback((cat: string) => {
    setActiveCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) {
        next.delete(cat);
      } else {
        next.add(cat);
      }
      return next;
    });
  }, []);

  // Select all / clear all categories
  const allCategories = flowData ? Array.from(new Set(flowData.nodes.map(n => n.category))) : [];
  const selectAllCategories = () => setActiveCategories(new Set(allCategories));
  const clearCategories = () => setActiveCategories(new Set());

  // Pass ALL data -- NetworkGraph handles filtering internally
  const allNodes = flowData?.nodes ?? [];
  const allEdges = flowData?.edges ?? [];
  const totalEvents = allEdges.reduce((sum, e) => sum + (e.value || 0), 0);
  const uniqueNodes = new Set(allNodes.map(n => n.id)).size;
  const categoryList = Array.from(new Set(allNodes.map(n => n.category)));

  return (
    <TabQueryWrapper tab="network" isLoading={flowLoading} isError={flowError} error={flowErrorObj} onRetry={refetchFlow}>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <Network size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Network Topology</h2>
          <span className="text-xs text-cyber-textMuted font-mono">
            {uniqueNodes} nodes · {allEdges.length} connections · {(totalEvents || 0).toLocaleString()} events
          </span>
        </div>

        {/* Pagination Slider */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-cyber-textMuted font-mono">Show top:</span>
          <input
            type="range"
            min={10}
            max={Math.min(500, allNodes.length)}
            step={10}
            value={maxNodes}
            onChange={e => setMaxNodes(Number(e.target.value))}
            className="w-32 accent-cyber-accent"
          />
          <span className="text-xs font-mono text-cyber-accent w-10">{maxNodes}</span>
        </div>
      </div>

      {/* Category Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-cyber-textMuted font-mono mr-2">Filter:</span>
        <button
          onClick={activeCategories.size > 0 ? clearCategories : selectAllCategories}
          className={`text-xs px-2 py-1 rounded font-mono border transition-colors ${
            activeCategories.size === 0
              ? 'bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent'
              : 'bg-cyber-panel border-cyber-border text-cyber-textMuted hover:border-cyber-accent/30'
          }`}
        >
          {activeCategories.size > 0 ? 'Clear filters' : 'All' }
        </button>
        {categoryList.map(cat => {
          const isActive = activeCategories.size === 0 || activeCategories.has(cat);
          const color = COLORS[cat] || '#64748b';
          return (
            <button
              key={cat}
              onClick={() => toggleCategory(cat)}
              className={`text-xs px-2 py-1 rounded font-mono border transition-colors flex items-center gap-1.5 ${
                isActive
                  ? 'bg-cyber-panelHover border-cyber-border'
                  : 'bg-cyber-panel/50 border-cyber-border/30 opacity-50'
              }`}
              style={isActive ? {} : {}}
            >
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
              <span className={isActive ? 'text-cyber-text' : 'text-cyber-textMuted/50'}>{cat}</span>
            </button>
          );
        })}
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          title="Total Events"
          value={totalEvents}
          subtitle="Last 24 hours"
          icon={<Activity size={14} className="text-cyber-accent" />}
          color="#00e5ff"
          trend={{ value: 12, positive: true }}
        />
        <StatCard
          title="Unique Nodes"
          value={uniqueNodes}
          subtitle="Active connections"
          icon={<Server size={14} className="text-cyber-purple" />}
          color="#8338ec"
        />
        <StatCard
          title="Categories"
          value={categoryList.length}
          subtitle="Traffic types"
          icon={<Globe size={14} className="text-cyber-green" />}
          color="#00ff88"
        />
        <StatCard
          title="Blocked"
          value={stats.blocked_24h || 0}
          subtitle="24h block count"
          icon={<Shield size={14} className="text-cyber-red" />}
          color="#ff1744"
        />
      </div>

      {/* Main Visualization */}
      <NetworkGraph
        nodes={allNodes}
        edges={allEdges}
        maxNodes={maxNodes}
        activeCategories={activeCategories}
        totalNodeCount={uniqueNodes}
        totalEdgeCount={allEdges.length}
      />

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <TrafficDistribution stats={stats} />
        <InterfaceTraffic stats={stats} />
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <CategoryStats stats={stats} />
        <TopSourcesTable stats={stats} />
      </div>
    </div>
    </TabQueryWrapper>
  );
}