// ═══════════════════════════════════════════════════
// Flows Tab - IP communication Sankey diagram
// With network clustering, expandable nodes, edge threshold
// ═══════════════════════════════════════════════════

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData, IpFlowClusterData } from '@/types';
import { GitMerge, Globe2, Layers, ChevronDown, ChevronUp, SlidersHorizontal } from 'lucide-react';

import { FlowsSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';
import { NETWORK, CYBER } from '../../utils/colors';

const CLUSTER_COLORS = NETWORK;

// ── By-IP view (original, for comparison) ──
function IpFlowView({ data }: { data: IpFlowData }) {
  const nodes = data.nodes.slice(0, 20);
  const edges = data.edges.slice(0, 50);

  const categoryColors = NETWORK;

  return (
    <div className="cyber-card p-4 relative">
      <div className="overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
        <svg className="w-full min-w-[600px]" viewBox="0 0 1200 500" preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="glow-ip">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Draw edges */}
          {edges.map((edge, i) => {
            const srcIdx = nodes.findIndex(n => n.id === edge.source);
            const tgtIdx = nodes.findIndex(n => n.id === edge.target);
            if (srcIdx === -1 || tgtIdx === -1) return null;
            const srcNode = nodes[srcIdx];
            const tgtNode = nodes[tgtIdx];
            const x1 = 150;
            const y1 = 50 + srcIdx * 22;
            const x2 = 1050;
            const y2 = 50 + tgtIdx * 22;

            return (
              <line
                key={`edge-${i}`}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke={categoryColors[srcNode.category] || CYBER.textMuted}
                strokeWidth={Math.max(Math.min(edge.value / 5, 4), 1)}
                opacity={0.3 + Math.min(edge.value / 50, 0.5)}
                filter="url(#glow-ip)"
              />
            );
          })}

          {/* Draw source nodes (left) */}
          {nodes.map((node, i) => (
            <g key={`src-${i}`} className="cursor-pointer">
              <circle
                cx={150}
                cy={50 + i * 22}
                r={Math.max(Math.min(node.count / 10, 16), 6)}
                fill={categoryColors[node.category] || CYBER.textMuted}
                opacity={0.8}
                filter="url(#glow-ip)"
              />
              <text
                x={130}
                y={50 + i * 22}
                fill={CYBER.textMuted}
                fontSize="9"
                textAnchor="end"
                dominantBaseline="middle"
                fontFamily="monospace"
              >
                {node.label.length > 12 ? node.label.slice(0, 10) + '\u2026' : node.label}
              </text>
            </g>
          ))}

          {/* Draw target nodes (right) */}
          {nodes.map((node, i) => (
            <g key={`tgt-${i}`} className="cursor-pointer">
              <circle
                cx={1050}
                cy={50 + i * 22}
                r={Math.max(Math.min(node.count / 10, 16), 6)}
                fill={categoryColors[node.category] || CYBER.textMuted}
                opacity={0.8}
                filter="url(#glow-ip)"
              />
              <text
                x={1070}
                y={50 + i * 22}
                fill={CYBER.textMuted}
                fontSize="9"
                textAnchor="start"
                dominantBaseline="middle"
                fontFamily="monospace"
              >
                {node.label.length > 12 ? node.label.slice(0, 10) + '\u2026' : node.label}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6 mt-4 pt-3 border-t border-cyber-border">
        {Object.entries(categoryColors).map(([cat, color]) => (
          <div key={cat} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}60` }} />
            <span className="text-xs text-cyber-textMuted">{cat}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── By-Network cluster view ──
function ClusterFlowView({ data, expandCluster, setExpandCluster, threshold, setThreshold }: {
  data: IpFlowClusterData;
  expandCluster: string | null;
  setExpandCluster: (v: string | null) => void;
  threshold: number;
  setThreshold: (v: number) => void;
}) {
  const nodes = data.nodes;
  const edges = data.edges;
  const clusters = data.clusters;

  // Determine which clusters actually have data
  const activeClusters = Object.values(clusters).filter(c => c.ip_count > 0);
  const activeClusterKeys = activeClusters.map(c => c.category);

  // Layout: cluster nodes in a circular-ish arrangement, expanded IPs in a column
  const svgW = 1100;
  const svgH = Math.max(500, nodes.length * 30 + 100);

  // Calculate positions
  const clusterPositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};

    // If a cluster is expanded, its IPs go on the left in a column
    // Other cluster nodes go on the right side
    const nonExpandedClusters = activeClusterKeys.filter(k => k !== expandCluster);
    const expandedClusterKey = expandCluster && clusters[expandCluster] ? expandCluster : null;

    // Position non-expanded clusters on the right side in a vertical layout
    const centerY = svgH / 2;
    nonExpandedClusters.forEach((key, i) => {
      const y = 80 + i * ((svgH - 160) / Math.max(nonExpandedClusters.length - 1, 1));
      positions[`cluster:${key}`] = { x: svgW - 180, y: Math.max(60, Math.min(y, svgH - 60)) };
    });

    // Position expanded IPs on the left side
    if (expandedClusterKey) {
      const expandedNodes = nodes.filter(n => !n.is_cluster);
      expandedNodes.forEach((node, i) => {
        const y = 60 + i * ((svgH - 120) / Math.max(expandedNodes.length - 1, 1));
        positions[node.id] = { x: 180, y: Math.max(40, Math.min(y, svgH - 40)) };
      });
    }

    return positions;
  }, [nodes, activeClusterKeys, expandCluster, clusters, svgH]);

  return (
    <div className="cyber-card p-4 relative">
      {/* Controls bar */}
      <div className="flex flex-wrap items-center gap-4 mb-4 pb-3 border-b border-cyber-border">
        {/* Edge threshold slider */}
        <div className="flex items-center gap-2">
          <SlidersHorizontal size={14} className="text-cyber-purple" />
          <label className="text-xs text-cyber-textMuted uppercase tracking-wider">Edge threshold</label>
          <input
            type="range"
            min={0}
            max={500}
            step={10}
            value={threshold}
            onChange={e => setThreshold(Number(e.target.value))}
            className="w-32 accent-cyber-purple"
          />
          <span className="text-xs font-mono text-cyber-purple min-w-[3ch]">{threshold}</span>
          <span className="text-xs text-cyber-textMuted">events</span>
        </div>

        {/* Active clusters count */}
        <div className="flex items-center gap-2 ml-auto">
          <span className="text-xs text-cyber-textMuted">
            {nodes.length} nodes · {edges.length} edges · {activeClusterKeys.length} networks
          </span>
        </div>
      </div>

      <div className="overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
        <svg className="w-full min-w-[600px]" viewBox={`0 0 ${svgW} ${svgH}`} preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="glow-cluster">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Draw edges */}
          {edges.map((edge, i) => {
            const srcPos = clusterPositions[edge.source];
            const tgtPos = clusterPositions[edge.target];
            if (!srcPos || !tgtPos) return null;

            // Find source node for color
            const srcNode = nodes.find(n => n.id === edge.source);
            const color = srcNode?.color || CYBER.textMuted;

            // Curved bezier for cleaner look
            const mx = (srcPos.x + tgtPos.x) / 2;
            const my = (srcPos.y + tgtPos.y) / 2 - 20;

            return (
              <g key={`edge-${i}`}>
                <path
                  d={`M ${srcPos.x} ${srcPos.y} Q ${mx} ${my} ${tgtPos.x} ${tgtPos.y}`}
                  fill="none"
                  stroke={color}
                  strokeWidth={Math.max(Math.min(edge.value / 20, 10), 1.5)}
                  opacity={0.25 + Math.min(edge.value / 200, 0.5)}
                  filter="url(#glow-cluster)"
                />
                {/* Edge value label on hover area */}
                <title>{`${edge.source} \u2192 ${edge.target}: ${edge.value.toLocaleString()} events`}</title>
              </g>
            );
          })}

          {/* Draw nodes */}
          {nodes.map((node, i) => {
            const pos = clusterPositions[node.id];
            if (!pos) return null;

            const r = node.is_cluster
              ? Math.max(20 + Math.min(node.count / 50, 20), 18)
              : Math.max(6 + Math.min(node.count / 10, 8), 4);

            return (
              <g
                key={`node-${i}`}
                className={node.is_cluster ? 'cursor-pointer' : ''}
                onClick={() => {
                  if (node.is_cluster) {
                    setExpandCluster(expandCluster === node.id.replace('cluster:', '') ? null : node.id.replace('cluster:', ''));
                  }
                }}
              >
                {/* Cluster node: rounded rectangle */}
                {node.is_cluster ? (
                  <>
                    <rect
                      x={pos.x - r}
                      y={pos.y - r * 0.6}
                      width={r * 2}
                      height={r * 1.2}
                      rx={8}
                      fill={node.color}
                      opacity={0.25}
                      stroke={node.color}
                      strokeWidth={2}
                      filter="url(#glow-cluster)"
                    />
                    <text
                      x={pos.x}
                      y={pos.y - 4}
                      fill={node.color}
                      fontSize="13"
                      fontWeight="bold"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontFamily="monospace"
                    >
                      {node.label}
                    </text>
                    <text
                      x={pos.x}
                      y={pos.y + 12}
                      fill={CYBER.textMuted}
                      fontSize="10"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontFamily="monospace"
                    >
                      {node.ip_count} IPs · {(node.count || 0).toLocaleString()} events
                    </text>
                    {/* Expand indicator */}
                    <text
                      x={pos.x}
                      y={pos.y + r * 0.6 + 14}
                      fill={CYBER.textMuted}
                      fontSize="8"
                      textAnchor="middle"
                      dominantBaseline="middle"
                    >
                      {expandCluster === node.label ? '\u25B2 Collapse' : '\u25BC Expand'}
                    </text>
                  </>
                ) : (
                  // Expanded IP node: small circle
                  <>
                    <circle
                      cx={pos.x}
                      cy={pos.y}
                      r={r}
                      fill={node.color}
                      opacity={0.7}
                      filter="url(#glow-cluster)"
                    />
                    <text
                      x={pos.x - r - 6}
                      y={pos.y}
                      fill={CYBER.textMuted}
                      fontSize="9"
                      textAnchor="end"
                      dominantBaseline="middle"
                      fontFamily="monospace"
                    >
                      {node.label}
                    </text>
                  </>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Cluster legend */}
      <div className="flex items-center gap-6 mt-4 pt-3 border-t border-cyber-border flex-wrap">
        {activeClusterKeys.map(cat => (
          <div
            key={cat}
            className="flex items-center gap-2 cursor-pointer hover:opacity-80"
            onClick={() => setExpandCluster(expandCluster === cat ? null : cat)}
          >
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: CLUSTER_COLORS[cat], boxShadow: `0 0 8px ${CLUSTER_COLORS[cat]}60` }} />
            <span className={`text-xs ${expandCluster === cat ? 'text-cyber-text font-bold' : 'text-cyber-textMuted'}`}>
              {cat} ({clusters[cat]?.ip_count || 0} IPs)
            </span>
            {expandCluster === cat && (
              <ChevronUp size={10} className="text-cyber-purple" />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main FlowsTab Component ──
export default function FlowsTab() {
  const [viewMode, setViewMode] = useState<'by-ip' | 'by-network'>('by-network');
  const [expandCluster, setExpandCluster] = useState<string | null>(null);
  const [threshold, setThreshold] = useState<number>(100);

  // By-IP data (original)
  const { data: ipData, isLoading: ipLoading, isError: ipError, error: ipErrorObj, refetch: ipRefetch } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
    enabled: viewMode === 'by-ip',
  });

  // By-Network cluster data
  const { data: clusterData, isLoading: clusterLoading, isError: clusterError, error: clusterErrorObj, refetch: clusterRefetch } = useQuery<IpFlowClusterData>({
    queryKey: ['ip-flow-clusters', expandCluster, threshold],
    queryFn: () => api.ipFlowClusters({ expand: expandCluster ?? undefined, threshold: threshold || undefined }),
    refetchInterval: 30000,
    enabled: viewMode === 'by-network',
  });

  const isLoading = viewMode === 'by-ip' ? ipLoading : clusterLoading;
  const isError = viewMode === 'by-ip' ? ipError : clusterError;
  const error = viewMode === 'by-ip' ? ipErrorObj : clusterErrorObj;
  const refetch = viewMode === 'by-ip' ? ipRefetch : clusterRefetch;

  if (isLoading) return <FlowsSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Flow Map" />;

  // Summary data from whichever view is active
  const allNodes = clusterData?.nodes || ipData?.nodes || [];
  const allEdges = clusterData?.edges || ipData?.edges || [];

  return (
    <div className="space-y-4">
      {/* Header with toggle */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <GitMerge size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">IP Flow Map</h2>

        {/* View mode toggle */}
        <div className="flex items-center ml-auto bg-cyber-panel/80 border border-cyber-border rounded-lg overflow-hidden">
          <button
            onClick={() => { setViewMode('by-network'); setExpandCluster(null); }}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'by-network'
                ? 'bg-cyber-purple/20 text-cyber-purple border-r border-cyber-border'
                : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panelHover'
            }`}
          >
            <Globe2 size={12} />
            By Network
          </button>
          <button
            onClick={() => { setViewMode('by-ip'); setExpandCluster(null); }}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'by-ip'
                ? 'bg-cyber-purple/20 text-cyber-purple'
                : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panelHover'
            }`}
          >
            <Layers size={12} />
            By IP
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-cyber-accent">{allNodes.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Nodes</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-pink">{allEdges.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Edges</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-green">
            {allEdges.reduce((s, e) => s + (e.value || 0), 0).toLocaleString()}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Total Events</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-purple">
            {new Set(allNodes.map(n => n.category)).size}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Categories</div>
        </div>
      </div>

      {/* Visualization */}
      {viewMode === 'by-network' && clusterData ? (
        <ClusterFlowView
          data={clusterData}
          expandCluster={expandCluster}
          setExpandCluster={setExpandCluster}
          threshold={threshold}
          setThreshold={setThreshold}
        />
      ) : (
        ipData && <IpFlowView data={ipData} />
      )}

      {/* Top flows table */}
      {allEdges.length > 0 && (
        <div className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Layers size={14} className="text-cyber-textMuted" />
            <h3 className="text-sm font-bold text-cyber-textMuted uppercase tracking-wider">Top Flows</h3>
          </div>
          <div className="cyber-table-responsive overflow-x-auto">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Events</th>
                </tr>
              </thead>
              <tbody>
                {allEdges.sort((a, b) => (b.value || 0) - (a.value || 0)).slice(0, 10).map((edge, i) => (
                  <tr key={i}>
                    <td className="font-mono text-sm">
                      <span className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{
                          backgroundColor: CLUSTER_COLORS[edge.source.replace('cluster:', '')] || CYBER.textMuted
                        }} />
                        {edge.source.replace('cluster:', '').replace(/\./g, '').length > 12
                          ? edge.source.length > 15 ? edge.source.slice(0, 13) + '\u2026' : edge.source
                          : edge.source}
                      </span>
                    </td>
                    <td className="font-mono text-sm">
                      <span className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{
                          backgroundColor: CLUSTER_COLORS[edge.target.replace('cluster:', '')] || CYBER.textMuted
                        }} />
                        {edge.target.replace('cluster:', '').replace(/\./g, '').length > 12
                          ? edge.target.length > 15 ? edge.target.slice(0, 13) + '\u2026' : edge.target
                          : edge.target}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="cyber-progress-track w-24">
                          <div
                            className="cyber-progress-fill bg-gradient-to-r from-cyber-purple to-neon-pink"
                            style={{ width: `${Math.min((edge.value / (allEdges[0]?.value || 1)) * 100, 100)}%` }}
                          />
                        </div>
                        <span className="font-mono text-sm">{edge.value.toLocaleString()}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Complementary view hint */}
      <div className="cyber-card p-3 border-dashed">
        <div className="flex items-center gap-2 text-xs text-cyber-textMuted">
          <Globe2 size={12} />
          <span>
            For a detailed matrix view of source &rarr; destination flows, see the{' '}
            <button
              onClick={() => { window.location.hash = '#ipflow'; }}
              className="text-cyber-purple hover:underline"
            >
              IP Flow
            </button>{' '}
            tab.
          </span>
        </div>
      </div>
    </div>
  );
}