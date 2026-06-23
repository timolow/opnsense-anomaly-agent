// ═══════════════════════════════════════════════════
// IDS Tab - Intrusion Detection System
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IdsData } from '@/types';
import { Eye, AlertTriangle, Shield } from 'lucide-react';
import { TabSkeleton } from '../SkeletonLoaders';
import { QueryErrorState } from '../TabErrorBoundary';

export default function IdsTab() {
  const { data: summary, error: summaryError, isError: summaryIsError, refetch: refetchSummary } = useQuery<IdsData['summary']>({
    queryKey: ['ids-summary'],
    queryFn: api.idsSummary,
    refetchInterval: 30000,
  });

  const { data: signatures = [] } = useQuery<IdsData['signatures'][]>({
    queryKey: ['ids-signatures'],
    queryFn: api.idsSignatures,
    refetchInterval: 30000,
  });

  const { data: anomalies = [] } = useQuery<IdsData['anomalies'][]>({
    queryKey: ['ids-anomalies'],
    queryFn: api.idsAnomalies,
    refetchInterval: 30000,
  });

  if (summaryIsError && summaryError) return <QueryErrorState error={summaryError} isError={summaryIsError} onRetry={refetchSummary} tabName="IDS" />;
  if (!summary) {
    return <TabSkeleton tab="ids" />;
  }

  const totalEvents = summary.total_events ?? 0;
  const sigCount = summary.signatures ?? 0;
  const anomaliesDetected = summary.anomalies_detected ?? 0;
  const events24h = summary.events_24h ?? 0;

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
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-cyan">{totalEvents.toLocaleString()}</div>
          <div className="cyber-stat-label">Total Events</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-pink">{sigCount.toLocaleString()}</div>
          <div className="cyber-stat-label">Signatures</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-yellow">{anomaliesDetected.toLocaleString()}</div>
          <div className="cyber-stat-label">Anomalies</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="text-2xl font-bold font-mono text-neon-green">{events24h.toLocaleString()}</div>
          <div className="cyber-stat-label">24h Events</div>
        </div>
      </div>

      {/* Top Signatures */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">
          Top Signatures {signatures.length === 0 && '(none detected)'}
        </h3>
        {signatures.length === 0 ? (
          <div className="text-center py-8 text-cyber-textMuted">
            <Shield size={24} className="mx-auto mb-2 opacity-50" />
            <div>No IDS signatures detected yet.</div>
            <div className="text-xs mt-1">IDS data requires Suricata/Snort events in the syslog pipeline.</div>
          </div>
        ) : (
          <div className="cyber-table-responsive"><table className="cyber-table">
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
                  <td className="font-mono">{(sig.triggered_count || 0).toLocaleString()}</td>
                  <td className="text-cyber-textMuted">{sig.last_triggered || 'N/A'}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {/* Anomalies */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">IDS Anomalies</h3>
        {anomalies.length === 0 ? (
          <div className="text-center py-6 text-cyber-textMuted text-sm">No IDS anomalies detected</div>
        ) : (
          <div className="space-y-2">
            {anomalies.map((a: any, i: number) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded bg-cyber-panelHover">
                <AlertTriangle size={14} className={a.severity === 'CRITICAL' ? 'text-cyber-red' : 'text-cyber-yellow'} />
                <span className="text-sm font-semibold flex-1">{a.type} ({a.count || 0})</span>
                <span className="font-mono text-xs text-cyber-textMuted">{a.source_ip || 'N/A'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
