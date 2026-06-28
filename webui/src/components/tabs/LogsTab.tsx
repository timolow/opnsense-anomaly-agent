// ═══════════════════════════════════════════════════
// Logs Tab - Merged: Syslogs + DNS Queries + Query Logs
// Sub-tabs for each log type with search/filter
// ═══════════════════════════════════════════════════

import { useState } from 'react';
import { FileText, Search, Database, Filter, ChevronDown, ChevronUp } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { EventsData, DnsQueryData } from '@/types';

import { SyslogsSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError, EmptyStateBanner } from '../../components/TabShell';

type LogSubTab = 'syslogs' | 'dns' | 'query';

// ── Sub-tab bar ──
function SubTabBar({ active, onChange }: { active: LogSubTab; onChange: (t: LogSubTab) => void }) {
  const tabs: { id: LogSubTab; label: string; icon: React.ReactNode; desc: string }[] = [
    { id: 'syslogs', label: 'Syslogs', icon: <FileText size={14} />, desc: 'Firewall events' },
    { id: 'dns', label: 'DNS', icon: <Database size={14} />, desc: 'DNS queries' },
    { id: 'query', label: 'Query Logs', icon: <Search size={14} />, desc: 'Search by IP/date' },
  ];

  return (
    <div className="flex gap-1 bg-cyber-panel/50 border border-cyber-border rounded-lg p-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          title={t.desc}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-md text-sm font-medium transition-all cursor-pointer ${
            active === t.id
              ? 'bg-cyber-accent/15 text-cyber-accent shadow-[inset_0_0_15px_rgba(0,229,255,0.05)]'
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
// Syslogs sub-view
// ═══════════════════════════════════════════════════
function SyslogsView() {
  const { data, isLoading, isError, error, refetch } = useQuery<EventsData>({
    queryKey: ['events'],
    queryFn: () => api.events(100, 0),
    refetchInterval: 30000,
  });

  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  if (isLoading) return <SyslogsSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Syslogs" />;

  const filtered = data.events.filter((e) => {
    if (filter && !e.raw?.toLowerCase().includes(filter.toLowerCase()) &&
        !e.src_ip?.includes(filter) && !e.dst_ip?.includes(filter)) return false;
    if (typeFilter && e.action !== typeFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
            <input
              type="text"
              placeholder="Search raw logs, IPs..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="cyber-input pl-9 font-mono text-xs"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="cyber-select w-full sm:w-28 min-h-[44px]"
          >
            <option value="">All Actions</option>
            <option value="PASS">PASS</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="cyber-card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">Firewall Events</h3>
          <span className="text-xs text-cyber-textMuted font-mono">{data.total} total · {filtered.length} shown</span>
        </div>
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">
            <Filter size={32} className="mx-auto mb-2 opacity-30" />
            No events found
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="cyber-table text-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Interface</th>
                  <th>Rule</th>
                  <th>Raw</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 100).map((event: any, i: number) => (
                  <tr key={i} className="hover:bg-cyber-panel/30">
                    <td className="text-cyber-textMuted">{event.timestamp}</td>
                    <td>
                      <span className={`cyber-badge ${event.action === 'PASS' ? 'cyber-badge-pass' : 'cyber-badge-block'}`}>
                        {event.action}
                      </span>
                    </td>
                    <td className="font-mono">{event.proto || '-'}</td>
                    <td className="font-mono">{event.src_ip || '-'}</td>
                    <td className="font-mono">{event.dst_ip || '-'}</td>
                    <td className="font-mono text-xs">{event.interface || '-'}</td>
                    <td className="max-w-[150px] truncate font-mono">{event.rule_name || '-'}</td>
                    <td className="max-w-[300px] truncate font-mono text-cyber-textMuted">
                      {(event as any).raw || ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// DNS Queries sub-view
// ═══════════════════════════════════════════════════
function DnsView() {
  const { data, isLoading, isError, error, refetch } = useQuery<DnsQueryData>({
    queryKey: ['dns-queries'],
    queryFn: api.dnsQueries,
    refetchInterval: 30000,
  });

  if (isLoading) return <SyslogsSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="DNS" />;

  const d = data;
  const status = d?.data_source_status;
  const message = d?.empty_message;

  const responseTypeColor = (code: string) => {
    const c = String(code).toUpperCase();
    if (c === 'NOERROR') return 'text-cyber-green';
    if (c === 'NXDOMAIN') return 'text-cyber-yellow';
    if (c === 'SERVFAIL' || c === 'REFUSED') return 'text-cyber-red';
    return 'text-cyber-textMuted';
  };

  return (
    <div className="space-y-4">
      <EmptyStateBanner status={status} message={message} />

      {status === 'configured' && (
        <>
          {/* Summary stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="cyber-card p-3">
              <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Total Queries</div>
              <div className="text-2xl font-bold font-mono text-cyber-accent">{(d?.total || 0).toLocaleString()}</div>
            </div>
            <div className="cyber-card p-3">
              <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Top Domains</div>
              <div className="text-2xl font-bold font-mono text-cyber-green">{(d?.top_domains?.length || 0).toLocaleString()}</div>
            </div>
            <div className="cyber-card p-3">
              <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Top Clients</div>
              <div className="text-2xl font-bold font-mono text-cyber-purple">{(d?.top_clients?.length || 0).toLocaleString()}</div>
            </div>
            <div className="cyber-card p-3">
              <div className="text-xs text-cyber-textMuted uppercase tracking-wider">Time Range</div>
              <div className="text-sm font-mono text-cyber-text">Last 24 hours</div>
            </div>
          </div>

          {/* Top domains and clients */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {d?.top_domains && d.top_domains.length > 0 && (
              <div className="cyber-card p-4">
                <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Top Domains</h3>
                <div className="overflow-x-auto">
                  <table className="cyber-table">
                    <thead><tr><th>Domain</th><th>Queries</th></tr></thead>
                    <tbody>
                      {d.top_domains.slice(0, 20).map((dom: any, i: number) => (
                        <tr key={i}>
                          <td className="font-mono">{dom.domain}</td>
                          <td className="font-mono text-cyber-accent">{dom.count.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            {d?.top_clients && d.top_clients.length > 0 && (
              <div className="cyber-card p-4">
                <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Top DNS Clients</h3>
                <div className="overflow-x-auto">
                  <table className="cyber-table">
                    <thead><tr><th>Client IP</th><th>Queries</th></tr></thead>
                    <tbody>
                      {d.top_clients.slice(0, 20).map((c: any, i: number) => (
                        <tr key={i}>
                          <td className="font-mono">{c.client_ip}</td>
                          <td className="font-mono text-cyber-accent">{c.count.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Recent queries */}
          {d?.queries && d.queries.length > 0 && (
            <div className="cyber-card p-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">Recent DNS Queries</h3>
              <div className="overflow-x-auto">
                <table className="cyber-table">
                  <thead>
                    <tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Response</th></tr>
                  </thead>
                  <tbody>
                    {d.queries.slice(0, 50).map((q: any, i: number) => (
                      <tr key={i}>
                        <td className="text-cyber-textMuted font-mono text-xs">{new Date(q.timestamp).toLocaleTimeString()}</td>
                        <td className="font-mono text-xs">{q.client_ip}</td>
                        <td className="font-mono">{q.domain}</td>
                        <td className="font-mono text-xs">{q.query_type}</td>
                        <td className={`font-mono text-xs ${responseTypeColor(q.response_code)}`}>{q.response_code}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {status === 'no_data' && (
        <div className="cyber-card p-8 text-center">
          <div className="text-cyber-textMuted text-sm">DNS logging is configured but no queries have been recorded in the last 24 hours.</div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Query Logs sub-view
// ═══════════════════════════════════════════════════
function QueryLogsView() {
  const [srcIp, setSrcIp] = useState('');
  const [days, setDays] = useState('7');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSearch = async () => {
    setLoading(true);
    setError('');
    setResults([]);
    try {
      const params = new URLSearchParams({ days, limit: '100' });
      if (srcIp) params.set('src_ip', srcIp);
      const res = await fetch(`/api/logs?${params.toString()}`);
      if (!res.ok) throw new Error(`Search failed: ${res.status}`);
      const data = await res.json();
      setResults(data.logs || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Form */}
      <div className="cyber-card p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Source IP</label>
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
              <input
                type="text"
                placeholder="e.g. 192.168.1.100"
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                className="cyber-input pl-9 font-mono"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Days Back</label>
            <input
              type="number"
              min="1"
              max="90"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="cyber-input"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={handleSearch}
              disabled={loading}
              className="cyber-btn w-full flex items-center justify-center gap-2"
            >
              <Search size={14} /> Search
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="cyber-card p-4">
        {loading && results.length === 0 ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
          </div>
        ) : error ? (
          <div className="text-cyber-red text-sm text-center py-8">{error}</div>
        ) : results.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">
            <Filter size={32} className="mx-auto mb-2 opacity-30" />
            No results found. Enter a source IP and click Search, or leave blank to fetch recent logs.
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">Query Results</h3>
              <span className="text-xs text-cyber-textMuted font-mono">{results.length} results</span>
            </div>
            <div className="overflow-x-auto">
              <table className="cyber-table text-xs">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Dest IP</th>
                    <th>Dest Port</th>
                    <th>Rule Name</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((log: any, i: number) => (
                    <tr key={i} className="hover:bg-cyber-panel/30">
                      <td className="text-cyber-textMuted">{new Date(log.timestamp).toLocaleString()}</td>
                      <td>
                        <span className={`cyber-badge ${log.action === 'pass' ? 'cyber-badge-pass' : 'cyber-badge-block'}`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="font-mono">{log.proto?.toUpperCase()}</td>
                      <td className="font-mono">{log.src_ip}</td>
                      <td className="font-mono">{log.dst_ip}</td>
                      <td className="font-mono">{log.dst_port ?? '-'}</td>
                      <td className="font-mono text-xs">{log.rule_name || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Main LogsTab Component
// ═══════════════════════════════════════════════════
export default function LogsTab() {
  const [subTab, setSubTab] = useState<LogSubTab>('syslogs');

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <FileText size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Logs</h2>
      </div>

      {/* Sub-tab navigation */}
      <SubTabBar active={subTab} onChange={setSubTab} />

      {/* Sub-tab content */}
      {subTab === 'syslogs' && <SyslogsView />}
      {subTab === 'dns' && <DnsView />}
      {subTab === 'query' && <QueryLogsView />}
    </div>
  );
}
