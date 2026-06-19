// ═══════════════════════════════════════════════════
// IDS Tab - Intrusion Detection System
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IdsData } from '@/types';
import { Eye, AlertTriangle, Shield } from 'lucide-react';

export default function IdsTab() {
  const { data: summary } = useQuery<IdsData['summary']>({
    queryKey: ['ids-summary'],
    queryFn: api.idsSummary,
    refetchInterval: 30000,
  });

  const { data: signatures } = useQuery<IdsData['signatures'][]>({
    queryKey: ['ids-signatures'],
    queryFn: api.idsSignatures,
    refetchInterval: 30000,
  });

  const { data: anomalies } = useQuery<IdsData['anomalies'][]>({
    queryKey: ['ids-anomalies'],
    queryFn: api.idsAnomalies,
    refetchInterval: 30000,
  });

  if (!summary || !signatures || !anomalies) {
    return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-yellow/10 border border-cyber-yellow/20 flex items-center justify-center">
          <Eye size={16} className="text-cyber-yellow" />
        </div>
        <h2 className="text-lg font-bold">IDS - Intrusion Detection</h2>
        <span className="text-xs text-cyber-textMuted font-mono">Suricata/Snort</span>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-cyan">{summary.total_events.toLocaleString()}</div>
          <div className="cyber-stat-label">Total Events</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-pink">{summary.signatures}</div>
          <div className="cyber-stat-label">Signatures</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-yellow">{summary.anomalies_detected}</div>
          <div className="cyber-stat-label">Anomalies</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-green">{summary.events_24h.toLocaleString()}</div>
          <div className="cyber-stat-label">24h Events</div>
        </div>
      </div>

      {/* Top Signatures */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Top Signatures</h3>
        <table className="cyber-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Triggered</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {signatures.slice(0, 30).map((sig) => (
              <tr key={sig.id}>
                <td className="font-mono">{sig.id}</td>
                <td className="max-w-[200px] truncate">{sig.name}</td>
                <td><span className="cyber-badge cyber-badge-info">{sig.category}</span></td>
                <td>
                  <span className={`font-mono text-xs ${sig.severity === 'CRITICAL' ? 'text-cyber-red' : sig.severity === 'HIGH' ? 'text-cyber-orange' : 'text-cyber-yellow'}`}>
                    {sig.severity}
                  </span>
                </td>
                <td className="font-mono">{sig.triggered_count.toLocaleString()}</td>
                <td className="text-cyber-textMuted">{sig.last_triggered}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Anomalies */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">IDS Anomalies</h3>
        <div className="space-y-2">
          {anomalies.map((a: any, i: number) => (
            <div key={i} className="flex items-center gap-3 p-2 rounded bg-cyber-panelHover">
              <AlertTriangle size={14} className={a.severity === 'CRITICAL' ? 'text-cyber-red' : 'text-cyber-yellow'} />
              <span className="text-sm font-semibold flex-1">{a.type} ({a.count})</span>
              <span className="font-mono text-xs text-cyber-textMuted">{a.source_ip}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
