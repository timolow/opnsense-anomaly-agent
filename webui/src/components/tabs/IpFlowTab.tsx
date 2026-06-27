// ═══════════════════════════════════════════════════
// IP Flow Tab - Detailed IP communication table
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { Network, Filter } from 'lucide-react';
import { useState } from 'react';

import { IpFlowSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function IpFlowTab() {
  const [ipFilter, setIpFilter] = useState<string>('all');

  const { data, isLoading, isError, error, refetch } = useQuery<IpFlowData>({
    queryKey: ['ip-flow', ipFilter],
    queryFn: () => api.ipFlow(ipFilter === 'all' ? undefined : ipFilter),
    refetchInterval: 30000,
  });

  if (isLoading) return <IpFlowSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="IP Flow" />;

  // Aggregate edges by source-destination pair
  const edgeMap = new Map<string, { source: string; target: string; value: number }>();
  data.edges.forEach((edge) => {
    const key = `${edge.source}→${edge.target}`;
    const existing = edgeMap.get(key);
    if (existing) {
      existing.value += edge.value;
    } else {
      edgeMap.set(key, { source: edge.source, target: edge.target, value: edge.value });
    }
  });

  const sorted = Array.from(edgeMap.values()).sort((a, b) => b.value - a.value).slice(0, 50);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <Network size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">IP Flow Details</h2>
      </div>

      {/* IP version filter toggle */}
      <div className="cyber-card p-3 flex items-center gap-3">
        <Filter size={14} className="text-cyber-textMuted flex-shrink-0" />
        <span className="text-xs text-cyber-textMuted uppercase tracking-wider flex-shrink-0">IP Version:</span>
        <div className="flex gap-1">
          {['all', 'ipv4', 'ipv6'].map((opt) => (
            <button
              key={opt}
              onClick={() => setIpFilter(opt)}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition-all cursor-pointer ${
                ipFilter === opt
                  ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/40'
                  : 'bg-cyber-panelHover text-cyber-textMuted border border-cyber-border hover:text-cyber-text'
              }`}
            >
              {opt === 'all' ? 'All' : opt === 'ipv4' ? 'IPv4 Only' : 'IPv6 Only'}
            </button>
          ))}
        </div>
      </div>

      <div className="cyber-card p-4">
        <div className="cyber-table-responsive"><table className="cyber-table">
          <thead>
            <tr>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Events</th>
              <th>Direction</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={4} className="text-center text-cyber-textMuted py-8">
                  No flow data found for the selected filter.
                </td>
              </tr>
            ) : (
              sorted.map((edge, i) => (
                <tr key={i}>
                  <td className="font-mono">{edge.source}</td>
                  <td className="font-mono">{edge.target}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="cyber-progress-track w-24">
                        <div
                          className="cyber-progress-fill bg-gradient-to-r from-cyber-accent to-cyber-purple"
                          style={{ width: `${Math.min((edge.value / sorted[0].value) * 100, 100)}%` }}
                        />
                      </div>
                      <span className="font-mono">{edge.value.toLocaleString()}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`cyber-badge ${edge.source.startsWith('192.168') || edge.source.startsWith('10.') || edge.source.startsWith('fe80:') || edge.source.startsWith('fd') ? 'cyber-badge-info' : 'cyber-badge-block'}`}>
                      {edge.source.startsWith('192.168') || edge.source.startsWith('10.') || edge.source.startsWith('fe80:') || edge.source.startsWith('fd') ? 'LAN' : 'WAN'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
