// ═══════════════════════════════════════════════════
// Flows Tab - IP communication flow visualization
// Uses react-force-graph-2d for network topology
// ═══════════════════════════════════════════════════

import { useState, useMemo, useCallback, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import ForceGraph2D from 'react-force-graph-2d';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { GitMerge, Eye, Maximize2, Minimize2 } from 'lucide-react';
import { QueryErrorState } from '../TabErrorBoundary';
import { TabSkeleton } from '../SkeletonLoaders';

// ── Color Scheme ──
const COLORS: Record<string, string> = {
  LAN: '#00ff88', WAN: '#ff006e', VPN: '#8338ec', DMZ: '#ffbe0b', UNKNOWN: '#64748b',
};

// ── Flow Graph Component ──
function FlowGraph({ nodes, edges }: { nodes: IpFlowData['nodes']; edges: IpFlowData['edges'] }) {
  const graphRef = useRef<any>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [connectedIds, setConnectedIds] = useState<Set<string>>(new Set());

  // Prepare graph data
  const graphData = useMemo(() => {
    const nodeMap = new Map<string, any>();

    nodes.forEach(node => {
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

    const visibleEdges = edges.filter(edge =>
      nodeMap.has(edge.source) && nodeMap.has(edge.target)
    );

    const graphEdges = visibleEdges.map(edge => ({
      source: edge.source,
      target: edge.target,
      weight: edge.value || 1,
      color: COLORS[nodes.find(n => n.id === edge.source)?.category || 'UNKNOWN'] || '#64748b',
    }));

    return { nodes: Array.from(nodeMap.values()), links: graphEdges };
  }, [nodes, edges]);

  // Adaptive simulation params based on node count
  const nodeCount = graphData.nodes.length;
  const cooldownTicks = nodeCount > 200 ? 20 : nodeCount > 100 ? 50 : 150;
  const linkDistance = Math.max(20, Math.min(60, 3000 / Math.max(nodeCount, 10)));

  const getLinkColor = (link: any) => {
    const baseColor = link.color || '#64748b';
    return baseColor + '40';
  };

  const getNodeColor = useCallback((node: any) => {
    if (!hoveredNodeId) return node.color || '#64748b';
    const isConnected = connectedIds.has(node.id);
    const baseColor = node.color || '#64748b';
    return isConnected ? baseColor : baseColor + '25';
  }, [hoveredNodeId, connectedIds]);

  const getNodeCanvasObjectDraw = useCallback((node: any, ctx: any, globalScale: number) => {
    const nodeColor = node.color || '#64748b';
    const isDimmed = hoveredNodeId && !connectedIds.has(node.id);

    if (node.size >= 10 && nodeCount <= 100 && !isDimmed) {
      ctx.shadowColor = nodeColor;
      ctx.shadowBlur = 8;
    } else {
      ctx.shadowBlur = 0;
    }

    ctx.beginPath();
    ctx.arc(node.x || 0, node.y || 0, node.size, 0, 2 * Math.PI);

    if (isDimmed) {
      ctx.fillStyle = nodeColor + '25';
    } else {
      ctx.fillStyle = nodeColor + '80';
    }
    ctx.fill();
    ctx.shadowBlur = 0;

    const maxNodesForLabels = nodeCount > 150 ? 12 : nodeCount > 80 ? 8 : 6;
    const showLabel = node.size >= maxNodesForLabels || globalScale > 2;
    if (showLabel && !isDimmed) {
      const label = node.label || node.id;
      ctx.font = '8px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#e2e8f0';
      ctx.fillText(label, node.x || 0, (node.y || 0) - node.size - 4);
    }
  }, [hoveredNodeId, connectedIds, nodeCount]);

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

  const hoveredNodeData = hoveredNodeId ? graphData.nodes.find((n: any) => n.id === hoveredNodeId) : null;

  return (
    <div className="relative">
      {/* Graph Controls */}
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

      {/* Node + Edge Count Badge */}
      <div className="absolute top-2 left-2 z-10">
        <div className="cyber-card px-3 py-1.5 text-xs font-mono flex items-center gap-2">
          <span className="text-cyber-textMuted">{graphData.nodes.length} nodes</span>
          <span className="text-cyber-textMuted/50">&middot;</span>
          <span className="text-cyber-textMuted">{graphData.links.length} edges</span>
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
      <div className="cyber-card p-4 scanlines" style={{ height: '400px' }}>
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
          linkDistance={linkDistance}
          linkStrength={nodeCount > 100 ? 0.2 : 0.5}
          forceAlphaDecay={nodeCount > 200 ? 0.02 : 0.01}
          nodeRelSize={Math.max(4, Math.min(8, 800 / Math.max(nodeCount, 10)))}
          width={1200}
          height={400}
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

// ── Main FlowsTab Component ──
export default function FlowsTab() {
  const { data, isLoading, error, isError, refetch } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  if (isError) return <QueryErrorState error={error} isError={isError} onRetry={refetch} tabName="Flow Map" />;
  if (isLoading || !data) {
    return <TabSkeleton tab="flows" />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <GitMerge size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">IP Flow Map</h2>
        <span className="text-xs text-cyber-textMuted font-mono">Communication Matrix</span>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-cyan">{data.nodes.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Nodes</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-pink">{data.edges.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Edges</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-green">
            {data.edges.reduce((s, e) => s + e.value, 0).toLocaleString()}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Total Events</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-purple">
            {new Set(data.nodes.map(n => n.category)).size}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Categories</div>
        </div>
      </div>

      {/* Visualization - ForceGraph2D */}
      <FlowGraph nodes={data.nodes} edges={data.edges} />
    </div>
  );
}