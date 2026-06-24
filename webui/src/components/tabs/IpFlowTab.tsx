// ═══════════════════════════════════════════════════
// IP Flow Tab - Detailed IP communication table
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
import { Network } from 'lucide-react';

import { IpFlowSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function IpFlowTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<IpFlowData>({
    queryKey: ['ip-flow'],
    queryFn: api.ipFlow,
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

      <div className="cyber-card p-4 scanlines">
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
            {sorted.map((edge, i) => (
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
                  <span className={`cyber-badge ${edge.source.startsWith('192.168') || edge.source.startsWith('10.') ? 'cyber-badge-info' : 'cyber-badge-block'}`}>
                    {edge.source.startsWith('192.168') || edge.source.startsWith('10.') ? 'LAN' : 'WAN'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
