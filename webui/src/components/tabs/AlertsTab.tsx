// ═══════════════════════════════════════════════════
// AlertsTab - Merged: Alerts + Mutes + ZenArmor + IDS
// Threat intelligence hub with sub-tabs
// ═══════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { ShieldAlert, Ban, Shield, Eye, Search, Filter, X } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import type { AlertsData, MutesData, ZenArmorData, IdsData } from '@/types';
import { format_ip } from '@/utils/formatIp';
import { useStore } from '../../store';

import { AlertsSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';
import { AlertDetailPanel } from '../../components/AlertDetailPanel';

type AlertsSubTab = 'alerts' | 'mutes' | 'zenarmor' | 'ids';

// ── Sub-tab bar ──
function SubTabBar({ active, onChange }: { active: AlertsSubTab; onChange: (t: AlertsSubTab) => void }) {
  const tabs: { id: AlertsSubTab; label: string; icon: React.ReactNode }[] = [
    { id: 'alerts', label: 'Alerts', icon: <ShieldAlert size={14} /> },
    { id: 'mutes', label: 'Mutes', icon: <Ban size={14} /> },
    { id: 'zenarmor', label: 'ZenArmor', icon: <Shield size={14} /> },
    { id: 'ids', label: 'IDS', icon: <Eye size={14} /> },
  ];

  return (
    <div className="flex gap-1 bg-cyber-panel/50 border border-cyber-border rounded-lg p-1 overflow-x-auto">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-md text-sm font-medium transition-all cursor-pointer whitespace-nowrap ${
            active === t.id
              ? 'bg-cyber-red/15 text-cyber-red shadow-[inset_0_0_15px_rgba(255,0,64,0.05)]'
              : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panelHover'
          }`}
        >
          {t.icon}
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Alerts sub-view
// ═══════════════════════════════════════════════════
function AlertsView() {
  const { data, isLoading, isError, error, refetch } = useQuery<AlertsData>({
    queryKey: ['alerts'],
    queryFn: api.alerts,
    refetchInterval: 30000,
  });

  const filterSeverity = useStore((s) => s.filterSeverity);
  const setFilterSeverity = useStore((s) => s.setFilterSeverity);

  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<typeof data.anomalies[0] | null>(null);

  useEffect(() => {
    if (filterSeverity) setSeverityFilter(filterSeverity);
  }, [filterSeverity]);

  useEffect(() => {
    setFilterSeverity(severityFilter as '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW');
  }, [severityFilter, setFilterSeverity]);

  if (isLoading) return <AlertsSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Threat Alerts" />;

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
      <div className="flex items-center gap-3">
        <span className="text-xs text-cyber-textMuted font-mono">{data.anomalies.length} total</span>
        {severityFilter && (
          <button onClick={() => setSeverityFilter('')} className="flex items-center gap-1 text-xs font-mono text-cyber-cyan hover:text-cyber-cyan/80 transition-colors bg-cyber-cyan/10 border border-cyber-cyan/30 px-2 py-1 rounded">
            <X size={12} /> Clear filter
          </button>
        )}
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
            <input type="text" placeholder="Search IP, keyword..." value={filter} onChange={(e) => setFilter(e.target.value)} className="cyber-input pl-9" />
          </div>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="cyber-select w-full sm:w-32 min-h-[44px]">
            <option value="">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      <div className="cyber-card p-4">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted"><Filter size={32} className="mx-auto mb-2 opacity-30" />No alerts found</div>
        ) : (
          <div className="cyber-table-responsive">
            <div className="text-xs text-cyber-textMuted font-mono mb-2 px-1">Click any row for details &amp; suggested actions</div>
            <table className="cyber-table">
              <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Destination</th><th>Details</th></tr></thead>
              <tbody>
                {filtered.slice(0, 100).map((alert, i) => (
                  <tr key={i} onClick={() => setSelectedAlert(alert)} className={`cursor-pointer hover:bg-cyber-panel/30 ${alert.severity === 'CRITICAL' ? 'alert-pulse-critical' : ''}`}>
                    <td className="text-cyber-textMuted">{alert.timestamp}</td>
                    <td><span className={`cyber-badge ${severityColor(alert.severity)}`}>{alert.severity}</span></td>
                    <td className={`font-semibold ${alert.severity === 'CRITICAL' ? 'text-cyber-red' : alert.severity === 'HIGH' ? 'text-cyber-orange' : alert.severity === 'MEDIUM' ? 'text-cyber-yellow' : 'text-cyber-green'}`}>{alert.type}</td>
                    <td className="font-mono">{format_ip(alert.source_ip, alert.src_hostname)}</td>
                    <td className="font-mono">{format_ip(alert.destination_ip, alert.dst_hostname)}</td>
                    <td className="max-w-xs truncate text-cyber-textMuted">{alert.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <AlertDetailPanel alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Mutes sub-view
// ═══════════════════════════════════════════════════
function MutesView() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ip: '', duration: '1h', reason: '' });
  const [search, setSearch] = useState('');

  const { data: mutes = [], isLoading, isError, error, refetch } = useQuery<MutesData[]>({
    queryKey: ['mutes'],
    queryFn: api.mutes,
    refetchInterval: 15000,
  });

  const createMute = useMutation({
    mutationFn: api.createMute,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['mutes'] }); setForm({ ip: '', duration: '1h', reason: '' }); setShowForm(false); },
  });

  const deleteMute = useMutation({
    mutationFn: (id: string) => api.deleteMute(id),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['mutes'] }); },
  });

  if (isLoading) return <div className="cyber-card p-8 text-center text-cyber-textMuted">Loading mutes...</div>;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Mutes" />;

  const filtered = mutes.filter((m) => m.ip.includes(search) || m.reason.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-cyber-textMuted font-mono">{mutes.length} active mutes</span>
        <button onClick={() => setShowForm(!showForm)} className="cyber-btn flex items-center gap-2 text-sm">
          <Ban size={14} /> {showForm ? 'Cancel' : 'Add Mute'}
        </button>
      </div>

      {showForm && (
        <div className="cyber-card p-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <input type="text" placeholder="IP Address" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} className="cyber-input" />
            <select value={form.duration} onChange={(e) => setForm({ ...form, duration: e.target.value })} className="cyber-select">
              <option value="15m">15 minutes</option><option value="1h">1 hour</option><option value="6h">6 hours</option>
              <option value="24h">24 hours</option><option value="7d">7 days</option><option value="30d">30 days</option>
            </select>
            <input type="text" placeholder="Reason" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className="cyber-input" />
          </div>
          <div className="flex gap-2 mt-3">
            <button onClick={() => createMute.mutate(form)} disabled={!form.ip} className="cyber-btn-success">Apply Mute</button>
            <button onClick={() => setShowForm(false)} className="cyber-btn">Cancel</button>
          </div>
        </div>
      )}

      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
        <input type="text" placeholder="Search mutes..." value={search} onChange={(e) => setSearch(e.target.value)} className="cyber-input pl-9" />
      </div>

      <div className="cyber-card p-4">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">No active mutes</div>
        ) : (
          <div className="cyber-table-responsive"><table className="cyber-table">
            <thead><tr><th>IP</th><th>Duration</th><th>Reason</th><th>Created</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {filtered.map((mute) => (
                <tr key={mute.id}>
                  <td className="font-mono">{mute.ip}</td>
                  <td><span className="cyber-badge cyber-badge-info">{mute.duration}</span></td>
                  <td className="max-w-xs truncate">{mute.reason}</td>
                  <td className="text-cyber-textMuted">{mute.created}</td>
                  <td className="text-cyber-textMuted">{mute.expires}</td>
                  <td><button onClick={() => deleteMute.mutate(mute.id)} className="text-cyber-textMuted hover:text-cyber-red transition-colors"><X size={14} /></button></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// ZenArmor sub-view (inline)
// ═══════════════════════════════════════════════════
function ZenArmorView() {
  const { data: summary, isLoading: summaryLoading, isError: summaryIsError, error: summaryError, refetch: summaryRefetch } = useQuery<ZenArmorData['summary'] | null>({
    queryKey: ['zenarmor-summary'],
    queryFn: api.zenarmorSummary,
    refetchInterval: 30000,
  });
  const { data: policies = [] } = useQuery<ZenArmorData['policies'][]>({ queryKey: ['zenarmor-policies'], queryFn: api.zenarmorPolicies, refetchInterval: 30000 });
  const { data: anomalies = [] } = useQuery<ZenArmorData['anomalies'][]>({ queryKey: ['zenarmor-anomalies'], queryFn: api.zenarmorAnomalies, refetchInterval: 30000 });

  if (summaryLoading) return <div className="cyber-card p-8 text-center text-cyber-textMuted">Loading ZenArmor...</div>;
  if (summaryIsError && summaryError) return <TabQueryError error={summaryError} isError={summaryIsError} onRetry={summaryRefetch} tabName="ZenArmor" />;

  const status = summary?.data_source_status;
  const msg = summary?.empty_message;

  return (
    <div className="space-y-4">
      {status !== 'configured' && (
        <div className="cyber-card p-4">
          <div className="text-cyber-textMuted text-sm text-center">
            {status === 'not_configured' ? 'ZenArmor is not configured yet.' : 'Loading ZenArmor data...'}
          </div>
        </div>
      )}
      {status === 'configured' && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Total Events</div><div className="text-2xl font-bold font-mono text-cyber-accent">{(summary.total_events ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Policies</div><div className="text-2xl font-bold font-mono text-cyber-green">{(summary.policies_count ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Anomalies</div><div className="text-2xl font-bold font-mono text-cyber-orange">{(summary.anomalies_detected ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Events 24h</div><div className="text-2xl font-bold font-mono text-cyber-purple">{(summary.events_24h ?? 0).toLocaleString()}</div></div>
          </div>
          {policies.length > 0 && (
            <div className="cyber-card p-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Active Policies</h3>
              <div className="cyber-table-responsive"><table className="cyber-table">
                <thead><tr><th>Name</th><th>Action</th><th>Priority</th><th>Matched</th></tr></thead>
                <tbody>{policies.slice(0, 20).map((p: any, i) => (
                  <tr key={i}><td>{p.name}</td><td><span className="cyber-badge cyber-badge-info">{p.action}</span></td><td className="font-mono">{p.priority}</td><td className="font-mono">{(p.matched_count ?? 0).toLocaleString()}</td></tr>
                ))}</tbody>
              </table></div>
            </div>
          )}
          {anomalies.length > 0 && (
            <div className="cyber-card p-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Recent Anomalies</h3>
              <div className="cyber-table-responsive"><table className="cyber-table">
                <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead>
                <tbody>{anomalies.slice(0, 20).map((a: any, i) => (
                  <tr key={i}><td className="text-cyber-textMuted">{a.timestamp}</td><td>{a.type}</td><td><span className={`cyber-badge ${a.severity === 'CRITICAL' ? 'cyber-badge-block' : 'cyber-badge-info'}`}>{a.severity}</span></td><td className="max-w-xs truncate text-cyber-textMuted">{a.details}</td></tr>
                ))}</tbody>
              </table></div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// IDS sub-view (inline)
// ═══════════════════════════════════════════════════
function IdsView() {
  const { data: summary, isLoading, isError, error, refetch } = useQuery<IdsData['summary']>({
    queryKey: ['ids-summary'],
    queryFn: api.idsSummary,
    refetchInterval: 30000,
  });
  const { data: signatures = [] } = useQuery<IdsData['signatures'][]>({ queryKey: ['ids-signatures'], queryFn: api.idsSignatures, refetchInterval: 30000 });
  const { data: anomalies = [] } = useQuery<IdsData['anomalies'][]>({ queryKey: ['ids-anomalies'], queryFn: api.idsAnomalies, refetchInterval: 30000 });

  if (isLoading) return <div className="cyber-card p-8 text-center text-cyber-textMuted">Loading IDS...</div>;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="IDS" />;

  const status = summary?.data_source_status;

  return (
    <div className="space-y-4">
      {status !== 'configured' && (
        <div className="cyber-card p-4">
          <div className="text-cyber-textMuted text-sm text-center">
            {status === 'not_configured' ? 'IDS/Suricata is not configured yet.' : 'Loading IDS data...'}
          </div>
        </div>
      )}
      {status === 'configured' && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Total Events</div><div className="text-2xl font-bold font-mono text-cyber-accent">{(summary.total_events ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Signatures</div><div className="text-2xl font-bold font-mono text-cyber-green">{(summary.signatures ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Anomalies</div><div className="text-2xl font-bold font-mono text-cyber-orange">{(summary.anomalies_detected ?? 0).toLocaleString()}</div></div>
            <div className="cyber-card p-3"><div className="text-xs text-cyber-textMuted uppercase">Events 24h</div><div className="text-2xl font-bold font-mono text-cyber-purple">{(summary.events_24h ?? 0).toLocaleString()}</div></div>
          </div>
          {signatures.length > 0 && (
            <div className="cyber-card p-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Top Signatures</h3>
              <div className="cyber-table-responsive"><table className="cyber-table">
                <thead><tr><th>Signature</th><th>Severity</th><th>Count</th></tr></thead>
                <tbody>{signatures.slice(0, 20).map((s: any, i) => (
                  <tr key={i}><td className="max-w-xs truncate">{s.signature}</td><td><span className={`cyber-badge ${s.severity === 'CRITICAL' ? 'cyber-badge-block' : 'cyber-badge-info'}`}>{s.severity}</span></td><td className="font-mono">{(s.count ?? 0).toLocaleString()}</td></tr>
                ))}</tbody>
              </table></div>
            </div>
          )}
          {anomalies.length > 0 && (
            <div className="cyber-card p-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Recent Anomalies</h3>
              <div className="cyber-table-responsive"><table className="cyber-table">
                <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead>
                <tbody>{anomalies.slice(0, 20).map((a: any, i) => (
                  <tr key={i}><td className="text-cyber-textMuted">{a.timestamp}</td><td>{a.type}</td><td><span className={`cyber-badge ${a.severity === 'CRITICAL' ? 'cyber-badge-block' : 'cyber-badge-info'}`}>{a.severity}</span></td><td className="max-w-xs truncate text-cyber-textMuted">{a.details}</td></tr>
                ))}</tbody>
              </table></div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Main AlertsTab Component (merged threats hub)
// ═══════════════════════════════════════════════════
export default function AlertsTab() {
  const [subTab, setSubTab] = useState<AlertsSubTab>('alerts');

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-red/10 border border-cyber-red/20 flex items-center justify-center">
          <ShieldAlert size={16} className="text-cyber-red" />
        </div>
        <h2 className="text-lg font-bold">Alerts</h2>
      </div>
      <SubTabBar active={subTab} onChange={setSubTab} />
      {subTab === 'alerts' && <AlertsView />}
      {subTab === 'mutes' && <MutesView />}
      {subTab === 'zenarmor' && <ZenArmorView />}
      {subTab === 'ids' && <IdsView />}
    </div>
  );
}
