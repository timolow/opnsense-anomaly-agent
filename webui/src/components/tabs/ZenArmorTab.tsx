// ═══════════════════════════════════════════════════
// ZenArmor Tab - ZenArmor security gateway
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { ZenArmorData } from '@/types';
import { Shield, BarChart3, AlertTriangle, Target } from 'lucide-react';

export default function ZenArmorTab() {
  const { data: summary } = useQuery<ZenArmorData['summary'] | null>({
    queryKey: ['zenarmor-summary'],
    queryFn: api.zenarmorSummary,
    refetchInterval: 30000,
  });

  const { data: policies = [] } = useQuery<ZenArmorData['policies'][]>({
    queryKey: ['zenarmor-policies'],
    queryFn: api.zenarmorPolicies,
    refetchInterval: 30000,
  });

  const { data: anomalies = [] } = useQuery<ZenArmorData['anomalies'][]>({
    queryKey: ['zenarmor-anomalies'],
    queryFn: api.zenarmorAnomalies,
    refetchInterval: 30000,
  });

  if (!summary) {
    return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;
  }

  const totalEvents = summary.total_events ?? 0;
  const policiesCount = summary.policies_count ?? 0;
  const anomaliesDetected = summary.anomalies_detected ?? 0;
  const events24h = summary.events_24h ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
          <Shield size={16} className="text-cyber-green" />
        </div>
        <h2 className="text-lg font-bold">ZenArmor</h2>
        <span className="text-xs text-cyber-textMuted font-mono">Security Gateway</span>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <BarChart3 size={16} className="text-cyber-accent" />
            <span className="cyber-stat-label">Events</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-cyan">{totalEvents.toLocaleString()}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Target size={16} className="text-cyber-pink" />
            <span className="cyber-stat-label">Policies</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-pink">{policiesCount.toLocaleString()}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={16} className="text-cyber-yellow" />
            <span className="cyber-stat-label">Anomalies</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-yellow">{anomaliesDetected.toLocaleString()}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Shield size={16} className="text-cyber-green" />
            <span className="cyber-stat-label">24h Events</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-green">{events24h.toLocaleString()}</div>
        </div>
      </div>

      {/* Policies */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">
          Active Policies {policies.length === 0 && '(none detected)'}
        </h3>
        {policies.length === 0 ? (
          <div className="text-center py-8 text-cyber-textMuted">
            <Shield size={24} className="mx-auto mb-2 opacity-50" />
            <div>No ZenArmor policies detected yet.</div>
            <div className="text-xs mt-1">ZenArmor data requires OPNsense ZenArmor events in the syslog pipeline.</div>
          </div>
        ) : (
          <div className="cyber-table-responsive"><table className="cyber-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Category</th>
                <th>Action</th>
                <th>Status</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy: any, i: number) => (
                <tr key={policy.id || i}>
                  <td className="font-semibold">{policy.name}</td>
                  <td><span className="cyber-badge cyber-badge-info">{policy.category}</span></td>
                  <td><span className={`font-mono ${policy.action === 'block' ? 'text-cyber-red' : 'text-cyber-green'}`}>{policy.action}</span></td>
                  <td><span className={`cyber-badge ${policy.status === 'active' ? 'cyber-badge-pass' : 'cyber-badge-warning'}`}>{policy.status}</span></td>
                  <td className="font-mono">{(policy.events || 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {/* Anomalies */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Anomalies Detected</h3>
        {anomalies.length === 0 ? (
          <div className="text-center py-6 text-cyber-textMuted text-sm">No ZenArmor anomalies detected</div>
        ) : (
          <div className="space-y-3">
            {anomalies.map((a: any, i: number) => (
              <div key={i} className="flex items-center gap-4 p-3 rounded bg-cyber-panelHover">
                <div className={`w-3 h-3 rounded-full flex-shrink-0 ${a.severity === 'CRITICAL' ? 'bg-cyber-red animate-pulse' : a.severity === 'HIGH' ? 'bg-cyber-orange animate-pulse' : 'bg-cyber-yellow animate-pulse'}`} />
                <div className="flex-1 min-w-0">
                  <div className="font-semibold text-sm">{a.type} - {(a.count || 0)} events</div>
                  <div className="text-xs text-cyber-textMuted truncate">{a.description || ''}</div>
                </div>
                <span className="font-mono text-xs text-cyber-textMuted">{a.source_ip || 'N/A'}</span>
                <span className="font-mono text-xs text-cyber-textMuted">{a.timestamp || ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
