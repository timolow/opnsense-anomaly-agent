// ═══════════════════════════════════════════════════
// Alerts Tab - Anomaly detection alerts
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { AlertsData } from '@/types';
import { ShieldAlert, Search, Filter } from 'lucide-react';
import { useState } from 'react';

export default function AlertsTab() {
  const { data } = useQuery<AlertsData>({
    queryKey: ['alerts'],
    queryFn: api.alerts,
    refetchInterval: 30000,
  });

  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const filtered = data.anomalies.filter((a) => {
    if (filter && !a.details.toLowerCase().includes(filter.toLowerCase()) &&
        !a.source_ip.includes(filter) && !a.destination_ip.includes(filter)) return false;
    if (severityFilter && a.severity !== severityFilter) return false;
    return true;
  });

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-cyber-red border-cyber-red';
      case 'HIGH': return 'text-cyber-orange border-cyber-orange';
      case 'MEDIUM': return 'text-cyber-yellow border-cyber-yellow';
      default: return 'text-cyber-green border-cyber-green';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-red/10 border border-cyber-red/20 flex items-center justify-center">
          <ShieldAlert size={16} className="text-cyber-red" />
        </div>
        <h2 className="text-lg font-bold">Threat Alerts</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{data.anomalies.length} total</span>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <div className="flex-1 flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
            <input
              type="text"
              placeholder="Search IP, keyword..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="cyber-input pl-9"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="cyber-select w-32"
          >
            <option value="">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="cyber-card p-4 scanlines">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">
            <Filter size={32} className="mx-auto mb-2 opacity-30" />
            No alerts found
          </div>
        ) : (
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Type</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 100).map((alert, i) => (
                <tr key={i} className="hover:bg-cyber-panel/30">
                  <td className="text-cyber-textMuted">{alert.timestamp}</td>
                  <td>
                    <span className={`cyber-badge ${severityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span className={`font-semibold ${alert.severity === 'CRITICAL' ? 'text-cyber-red' : alert.severity === 'HIGH' ? 'text-cyber-orange' : alert.severity === 'MEDIUM' ? 'text-cyber-yellow' : 'text-cyber-green'}`}>
                      {alert.type}
                    </span>
                  </td>
                  <td className="font-mono">{alert.source_ip}</td>
                  <td className="font-mono">{alert.destination_ip}</td>
                  <td className="max-w-xs truncate text-cyber-textMuted">{alert.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
