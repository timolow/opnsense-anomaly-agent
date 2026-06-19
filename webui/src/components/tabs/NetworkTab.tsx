// ═══════════════════════════════════════════════════
// Network Tab - Network topology / visualization
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { Network as NetworkIcon } from 'lucide-react';

export default function NetworkTab() {
  const { data } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const nodes = data.nodes.slice(0, 30);
  const edges = data.edges.slice(0, 60);

  const categoryColor: Record<string, string> = {
    LAN: '#00ff88', WAN: '#ff006e', VPN: '#8338ec', DMZ: '#ffbe0b', UNKNOWN: '#64748b',
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <NetworkIcon size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Network Topology</h2>
        <span className="text-xs text-cyber-textMuted font-mono">
          {nodes.length} nodes · {edges.length} connections
        </span>
      </div>

      <div className="cyber-card p-4 scanlines">
        <svg width="100%" height="600" viewBox="0 0 1200 600" className="w-full">
          <defs>
            <filter id="netGlow">
              <feGaussianBlur stdDeviation="4" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>

          {/* Edges */}
          {edges.map((edge, i) => {
            const srcNode = nodes.find(n => n.id === edge.source);
            const tgtNode = nodes.find(n => n.id === edge.target);
            if (!srcNode || !tgtNode) return null;
            
            const x1 = 100 + (srcNode.size * 10);
            const y1 = 300 + Math.sin(i * 0.5) * 200;
            const x2 = 1100 - (tgtNode.size * 10);
            const y2 = 300 + Math.cos(i * 0.5) * 200;
            
            return (
              <line
                key={`edge-${i}`}
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke={categoryColor[srcNode.category] || '#64748b'}
                strokeWidth={Math.min(edge.value / 5, 4)}
                opacity={0.2 + Math.min(edge.value / 200, 0.8)}
                filter="url(#netGlow)"
              />
            );
          })}

          {/* Nodes */}
          {nodes.map((node, i) => (
            <g key={`node-${i}`}>
              <circle
                cx="100" cy={300 + (i - 15) * 15}
                r={Math.min(node.size, 24)}
                fill={categoryColor[node.category] || '#64748b'}
                opacity={0.4 + Math.min(node.count / 200, 0.6)}
                filter="url(#netGlow)"
              />
              <text
                x="100" y={300 + (i - 15) * 15 + 4}
                fill="#0a0e17" fontSize="9" textAnchor="middle"
                fontFamily="monospace" fontWeight="bold"
              >
                {node.label.length > 6 ? node.label.slice(0, 5) + '…' : node.label}
              </text>
            </g>
          ))}

          {/* Right side nodes */}
          {nodes.map((node, i) => (
            <g key={`node-r-${i}`}>
              <circle
                cx="1100" cy={300 + (i - 15) * 15}
                r={Math.min(node.size, 18)}
                fill={categoryColor[node.category] || '#64748b'}
                opacity={0.3 + Math.min(node.count / 200, 0.5)}
                filter="url(#netGlow)"
              />
              <text
                x="1100" y={300 + (i - 15) * 15 + 4}
                fill="#0a0e17" fontSize="9" textAnchor="middle"
                fontFamily="monospace" fontWeight="bold"
              >
                {node.label.length > 6 ? node.label.slice(0, 5) + '…' : node.label}
              </text>
            </g>
          ))}

          {/* Labels */}
          <text x="100" y="30" fill="#64748b" fontSize="11" textAnchor="middle" fontFamily="monospace">Source Network</text>
          <text x="1100" y="30" fill="#64748b" fontSize="11" textAnchor="middle" fontFamily="monospace">Destination Network</text>
        </svg>

        {/* Legend */}
        <div className="flex items-center gap-6 mt-4 pt-3 border-t border-cyber-border">
          {Object.entries(categoryColor).map(([cat, color]) => (
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
