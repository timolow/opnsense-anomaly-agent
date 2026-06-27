// ═══════════════════════════════════════════════════
// DNS Queries Tab - DNS query monitoring
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { DnsQueryData } from '@/types';
import { Search, Globe, Monitor } from 'lucide-react';

import { DnsQueriesSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError, EmptyStateBanner } from '../../components/TabShell';

// ── Top Domains Table ──
function TopDomainsTable({ domains }: { domains: Array<{ domain: string; count: number }> }) {
  if (domains.length === 0) return null;

  return (
    <div className="cyber-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Globe size={14} className="text-cyber-accent" />
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">Top Domains</h3>
      </div>
      <div className="cyber-table-responsive"><table className="cyber-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Queries</th>
          </tr>
        </thead>
        <tbody>
          {domains.slice(0, 20).map((d, i) => (
            <tr key={i}>
              <td className="font-mono">{d.domain}</td>
              <td className="font-mono text-cyber-accent">{d.count.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </div>
  );
}

// ── Top Clients Table ──
function TopClientsTable({ clients }: { clients: Array<{ client_ip: string; count: number }> }) {
  if (clients.length === 0) return null;

  return (
    <div className="cyber-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Monitor size={14} className="text-cyber-accent" />
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">Top DNS Clients</h3>
      </div>
      <div className="cyber-table-responsive"><table className="cyber-table">
        <thead>
          <tr>
            <th>Client IP</th>
            <th>Queries</th>
          </tr>
        </thead>
        <tbody>
          {clients.slice(0, 20).map((c, i) => (
            <tr key={i}>
              <td className="font-mono">{c.client_ip}</td>
              <td className="font-mono text-cyber-accent">{c.count.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </div>
  );
}

// ── Recent Queries Table ──
function RecentQueriesTable({ queries }: { queries: DnsQueryData['queries'] }) {
  if (queries.length === 0) return null;

  const responseTypeColor = (code: string) => {
    const c = String(code).toUpperCase();
    if (c === 'NOERROR') return 'text-cyber-green';
    if (c === 'NXDOMAIN') return 'text-cyber-yellow';
    if (c === 'SERVFAIL' || c === 'REFUSED') return 'text-cyber-red';
    return 'text-cyber-textMuted';
  };

  return (
    <div className="cyber-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <Search size={14} className="text-cyber-accent" />
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">Recent DNS Queries</h3>
      </div>
      <div className="cyber-table-responsive"><table className="cyber-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Response</th>
          </tr>
        </thead>
        <tbody>
          {queries.slice(0, 50).map((q, i) => (
            <tr key={i}>
              <td className="text-cyber-textMuted font-mono text-xs">
                {new Date(q.timestamp).toLocaleTimeString()}
              </td>
              <td className="font-mono text-xs">{q.client_ip}</td>
              <td className="font-mono">{q.domain}</td>
              <td className="font-mono text-xs">{q.query_type}</td>
              <td className={`font-mono text-xs ${responseTypeColor(q.response_code)}`}>
                {q.response_code}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </div>
  );
}

// ── Main Component ──
export default function DnsQueriesTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<DnsQueryData>({
    queryKey: ['dns-queries'],
    queryFn: api.dnsQueries,
    refetchInterval: 30000,
  });

  if (isLoading) return <DnsQueriesSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="DNS Queries" />;

  const d = data;
  const status = d?.data_source_status;
  const message = d?.empty_message;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <Search size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">DNS Query Logs</h2>
      </div>

      {/* Empty state banner */}
      <EmptyStateBanner status={status} message={message} />

      {/* Data panels - only show when configured */}
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

          {/* Top domains and clients side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <TopDomainsTable domains={d?.top_domains || []} />
            <TopClientsTable clients={d?.top_clients || []} />
          </div>

          {/* Recent queries */}
          <RecentQueriesTable queries={d?.queries || []} />
        </>
      )}

      {/* When not configured, we already show the banner above */}
      {/* When no_data but configured, show summary with zero values */}
      {status === 'no_data' && (
        <div className="cyber-card p-8 text-center">
          <div className="text-cyber-textMuted text-sm">
            DNS logging is configured but no queries have been recorded in the last 24 hours.
          </div>
        </div>
      )}
    </div>
  );
}
