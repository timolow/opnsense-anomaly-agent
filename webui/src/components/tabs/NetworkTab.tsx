// ═══════════════════════════════════════════════════
// Network Tab - Interactive network topology dashboard
// ═══════════════════════════════════════════════════

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import ForceGraph2D from 'react-force-graph-2d';
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { NETWORK, networkColor, CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';
import {
  Network, Activity, Globe, Shield, Server, Wifi, Radio,
  ArrowUpRight, ArrowDownRight, Eye, MousePointer2,
  Maximize2, Minimize2
} from 'lucide-react';

// ── Color Scheme (now from shared colors) ──
const COLORS = NETWORK;

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

// ── Force Graph Component ──
function NetworkGraph({ nodes, edges }: { nodes: any[]; edges: any[] }) {
  const graphRef = useRef<any>(null);
  const [hoveredNode, setHoveredNode] = useState<any>(null);
  const [showControls, setShowControls] = useState(true);

  // Prepare graph data
  const graphData = useMemo(() => {
    const nodeMap = new Map<string, any>();

    // Add nodes
    nodes.forEach(node => {
      const id = node.id || node.label;
      nodeMap.set(id, {
        id,
        label: node.label || id,
        size: Math.max(6, Math.min(20, (node.count || 0) / 50)),
        color: COLORS[node.category] || CYBER.textMuted,
        category: node.category,
        count: node.count || 0,
      });
    });

    // Add edges
    const graphEdges = edges.filter(edge => {
      const src = nodeMap.has(edge.source);
      const tgt = nodeMap.has(edge.target);
      return src && tgt;
    }).map(edge => ({
      source: edge.source,
      target: edge.target,
      weight: edge.value || 1,
      color: COLORS[edge.source?.category || 'UNKNOWN'],
    }));

    return { nodes: Array.from(nodeMap.values()), links: graphEdges };
  }, [nodes, edges]);

  const getNodeColor = (node: any) => node.color || CYBER.textMuted;
  const getLinkColor = (link: any) => {
    const baseColor = link.color || CYBER.textMuted;
    return baseColor + '40'; // Add transparency
  };

  const getNodeCanvasObjectDraw = useCallback((node: any, ctx: any, color: string, scale: number) => {
    const label = node.label || node.id;
    const fontSize = 8;
    const textWidth = ctx.measureText(label).width;

    // Draw glow effect
    ctx.shadowColor = color;
    ctx.shadowBlur = 10;
    ctx.beginPath();
    ctx.arc(node.x || 0, node.y || 0, node.size, 0, 2 * Math.PI);
    ctx.fillStyle = color + '80';
    ctx.fill();
    ctx.shadowBlur = 0;

    // Draw label
    ctx.font = `${fontSize}px monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = CYBER.text;
    ctx.fillText(label, node.x || 0, node.y || 0);
  }, []);

  return (
    <div className="relative">
      {/* Graph Controls */}
      {showControls && (
        <div className="absolute top-2 right-2 z-10 flex gap-2">
          <button
            onClick={() => graphRef.current?.zoomIn()}
            className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
            title="Zoom In"
          >
            <Maximize2 size={12} />
          </button>
          <button
            onClick={() => graphRef.current?.zoomOut()}
            className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
            title="Zoom Out"
          >
            <Minimize2 size={12} />
          </button>
          <button
            onClick={() => graphRef.current?.centerAt(600, 300).zoom(1)}
            className="w-8 h-8 rounded-md bg-cyber-panel border border-cyber-border flex items-center justify-center text-cyber-textMuted hover:text-cyber-accent hover:border-cyber-accent/50"
            title="Reset View"
          >
            <Eye size={12} />
          </button>
        </div>
      )}

      {/* Hover Info */}
      {hoveredNode && (
        <div className="absolute top-2 left-2 z-10 cyber-card p-3 text-xs font-mono">
          <div className="font-semibold" style={{ color: hoveredNode.color }}>{hoveredNode.label}</div>
          <div className="text-cyber-textMuted">Category: {hoveredNode.category}</div>
          <div className="text-cyber-textMuted">Events: {(hoveredNode.count || 0).toLocaleString()}</div>
        </div>
      )}

      {/* Force Graph */}
      <div className="cyber-card p-4 scanlines" style={{ height: '150px' }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          nodeLabel="label"
          nodeCanvasObject={getNodeCanvasObjectDraw}
          linkColor={getLinkColor}
          linkWidth={(link: any) => Math.max(0.5, Math.min(3, (link.weight || 1) / 20))}
          linkDirectionalArrowLength={(link: any) => Math.max(4, (link.weight || 1) / 5)}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.15}
          onNodeHover={(node) => {
            setHoveredNode(node || null);
            if (node) {
              // Highlight connected nodes
              const connectedIds = new Set<string>();
              connectedIds.add(node.id);
              graphData.links.forEach((link: any) => {
                if (link.source.id === node.id) connectedIds.add(link.target.id);
                if (link.target.id === node.id) connectedIds.add(link.source.id);
              });
              graphData.nodes.forEach((n: any) => {
                n.opacity = connectedIds.has(n.id) ? 1 : 0.2;
              });
            } else {
              graphData.nodes.forEach((n: any) => { n.opacity = 1; });
            }
          }}
          cooldownTicks={150}
          d3Force="forceLink"
          linkForce={-0.5}
          nodeRelSize={8}
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
    { name: 'External', value: byType.external || 0, color: CYBER.pink },
    { name: 'Unknown', value: byType.unknown || 0, color: CYBER.textMuted },
    { name: 'Internal', value: byType.internal || 0, color: CYBER.green },
    { name: 'VPN', value: byType.vpn || 0, color: CYBER.purple },
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
            contentStyle={RECHARTS_TOOLTIP}
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
      color: COLORS[s.category] || CYBER.textMuted,
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
          <XAxis type="number" domain={[0, 'auto']} tick={{}} axisLine={false} tickLine={false} />
          <YAxis
            dataKey="name"
            type="category"
            width={100}
            tick={{ fill: CYBER.textMuted, fontSize: 10, fontFamily: 'monospace' }}
          />
          <Tooltip
            contentStyle={RECHARTS_TOOLTIP}
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
    color: COLORS[name] || CYBER.textMuted,
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
            tick={{ fill: CYBER.textMuted, fontSize: 10, fontFamily: 'monospace' }}
          />
          <YAxis tick={{ fill: CYBER.textMuted, fontSize: 10, fontFamily: 'monospace' }} />
          <Tooltip
            contentStyle={RECHARTS_TOOLTIP}
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
                      background: `${COLORS[source.category] || CYBER.textMuted}15`,
                      color: COLORS[source.category] || CYBER.textMuted,
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
import { NetworkSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function NetworkTab() {
  const { data: flowData, isLoading: flowLoading, isError: flowError, error: flowErrorObj, refetch: flowRefetch } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  const { data: stats, isLoading: statsLoading } = useQuery<any>({
    queryKey: ['stats'],
    queryFn: api.stats,
    refetchInterval: 30000,
  });

  if (flowLoading || statsLoading) return <NetworkSkeleton />;
  if (flowError && flowErrorObj) return <TabQueryError error={flowErrorObj} isError={flowError} onRetry={flowRefetch} tabName="Network Topology" />;

  const nodes = flowData.nodes.slice(0, 30);
  const edges = flowData.edges.slice(0, 60);
  const totalEvents = edges.reduce((sum, e) => sum + (e.value || 0), 0);
  const uniqueNodes = new Set(nodes.map(n => n.id)).size;
  const categories = Array.from(new Set(nodes.map(n => n.category))).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <Network size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Network Topology</h2>
        <span className="text-xs text-cyber-textMuted font-mono">
          {uniqueNodes} nodes · {edges.length} connections · {(totalEvents || 0).toLocaleString()} events
        </span>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          title="Total Events"
          value={totalEvents}
          subtitle="Last 24 hours"
          icon={<Activity size={14} className="text-cyber-accent" />}
          color={CYBER.accent}
          trend={{ value: 12, positive: true }}
        />
        <StatCard
          title="Unique Nodes"
          value={uniqueNodes}
          subtitle="Active connections"
          icon={<Server size={14} className="text-cyber-purple" />}
          color={CYBER.purple}
        />
        <StatCard
          title="Categories"
          value={categories}
          subtitle="Traffic types"
          icon={<Globe size={14} className="text-cyber-green" />}
          color={CYBER.green}
        />
        <StatCard
          title="Blocked"
          value={stats.blocked_24h || 0}
          subtitle="24h block count"
          icon={<Shield size={14} className="text-cyber-red" />}
          color={CYBER.red}
        />
      </div>

      {/* Main Visualization */}
      <NetworkGraph nodes={nodes} edges={edges} />

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
  );
}