// ═══════════════════════════════════════════════════
// Flows Tab - IP communication Sankey diagram
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { GitMerge } from 'lucide-react';

export default function FlowsTab() {
  const { data } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const nodes = data.nodes.slice(0, 20);
  const edges = data.edges.slice(0, 50);

  const categoryColors: Record<string, string> = {
    LAN: '#00ff88',
    WAN: '#ff006e',
    VPN: '#8338ec',
    DMZ: '#ffbe0b',
    UNKNOWN: '#64748b',
  };

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
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-cyan">{nodes.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Nodes</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-pink">{edges.length}</div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Edges</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-green">
            {edges.reduce((s, e) => s + e.value, 0).toLocaleString()}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Total Events</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-purple">
            {new Set(nodes.map(n => n.category)).size}
          </div>
          <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Categories</div>
        </div>
      </div>

      {/* Visualization - Network graph using SVG */}
      <div className="cyber-card p-4 scanlines relative">
        <svg width="100%" height="500" viewBox="0 0 1200 500" className="w-full">
          <defs>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
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
                stroke={categoryColors[srcNode.category] || '#64748b'}
                strokeWidth={Math.max(Math.min(edge.value / 5, 4), 1)}
                opacity={0.3 + Math.min(edge.value / 50, 0.5)}
                filter="url(#glow)"
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
                fill={categoryColors[node.category] || '#64748b'}
                opacity={0.8}
                filter="url(#glow)"
              />
              <text
                x={130}
                y={50 + i * 22}
                fill="#64748b"
                fontSize="9"
                textAnchor="end"
                dominantBaseline="middle"
                fontFamily="monospace"
              >
                {node.label.length > 12 ? node.label.slice(0, 10) + '…' : node.label}
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
                fill={categoryColors[node.category] || '#64748b'}
                opacity={0.8}
                filter="url(#glow)"
              />
              <text
                x={1070}
                y={50 + i * 22}
                fill="#64748b"
                fontSize="9"
                textAnchor="start"
                dominantBaseline="middle"
                fontFamily="monospace"
              >
                {node.label.length > 12 ? node.label.slice(0, 10) + '…' : node.label}
              </text>
            </g>
          ))}
        </svg>

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
    </div>
  );
}
