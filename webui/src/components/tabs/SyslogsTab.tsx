// ═══════════════════════════════════════════════════
// Syslogs Tab - Syslog viewer
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { EventsData } from '@/types';
import { FileText, Search, Filter } from 'lucide-react';
import { useState } from 'react';
import { QueryErrorState } from '../TabErrorBoundary';
import { TabSkeleton } from '../SkeletonLoaders';

export default function SyslogsTab() {
  const { data, error, isError, refetch } = useQuery<EventsData>({
    queryKey: ['events'],
    queryFn: () => api.events(100, 0),
    refetchInterval: 30000,
  });

  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  if (isError) return <QueryErrorState error={error} isError={isError} onRetry={refetch} tabName="Syslogs" />;

  if (!data) return <TabSkeleton tab="syslogs" />;

  const filtered = data.events.filter((e) => {
    if (filter && !e.raw?.toLowerCase().includes(filter.toLowerCase()) &&
        !e.src_ip?.includes(filter) && !e.dst_ip?.includes(filter)) return false;
    if (typeFilter && e.action !== typeFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <FileText size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Syslogs</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{data.total} events</span>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
            <input
              type="text"
              placeholder="Search raw logs..."
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
            <option value="">All</option>
            <option value="PASS">PASS</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="cyber-card p-4 scanlines">
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
