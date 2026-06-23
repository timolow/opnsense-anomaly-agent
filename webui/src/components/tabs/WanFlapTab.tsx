// ═══════════════════════════════════════════════════
// WAN Flap Tab - WAN interface flap detection
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { Radio, AlertTriangle, RefreshCw } from 'lucide-react';
import TimelineChart from '../../components/charts/TimelineChart';
import { QueryErrorState } from '../TabErrorBoundary';
import { TabSkeleton } from '../SkeletonLoaders';

export default function WanFlapTab() {
  const { data, isLoading, error, isError, refetch } = useQuery<any>({
    queryKey: ['wan-flap'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/wan-flap');
        if (res.ok) return await res.json();
        return null;
      } catch { return null; }
    },
    refetchInterval: 30000,
  });

  if (isError) return <QueryErrorState error={error} isError={isError} onRetry={refetch} tabName="WAN Flap Detection" />;
  if (isLoading || !data) return <TabSkeleton tab="wan-flap" />;

  const flapData = data?.flaps || [];
  const stats = data?.stats || { total_flaps: 0, last_flap: 'N/A', avg_duration: 'N/A' };

  // Convert flap data to TimelineChart format
  const timelineData = flapData.slice(-24).map((f: { time: string; count: number }) => ({
    time: Math.floor(new Date(f.time).getTime() / 1000),
    value: f.count,
  }));

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-orange/10 border border-cyber-orange/20 flex items-center justify-center">
          <Radio size={16} className="text-cyber-orange" />
        </div>
        <h2 className="text-lg font-bold">WAN Flap Detection</h2>
        <span className="text-xs text-cyber-textMuted font-mono">Interface stability monitor</span>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-cyber-orange" />
            <span className="cyber-stat-label">Total Flaps</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-orange">{stats.total_flaps}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <RefreshCw size={14} className="text-cyber-accent" />
            <span className="cyber-stat-label">Last Flap</span>
          </div>
          <div className="text-sm font-bold font-mono text-neon-cyan">{stats.last_flap}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <RefreshCw size={14} className="text-cyber-green" />
            <span className="cyber-stat-label">Avg Duration</span>
          </div>
          <div className="text-sm font-bold font-mono text-neon-green">{stats.avg_duration}s</div>
        </div>
      </div>

      {/* Flap History - uPlot time series */}
      <TimelineChart
        title="Flap History (24h)"
        data={timelineData}
        isLoading={!data}
        height={250}
        className="scanlines"
      />

      {/* Flap Events */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Recent Flap Events</h3>
        {flapData.length === 0 ? (
          <div className="text-center py-8 text-cyber-textMuted">No recent flaps</div>
        ) : (
          <div className="cyber-timeline max-h-[300px] overflow-y-auto">
            {flapData.slice(0, 20).map((flap: { time: string; interface: string; duration: number }, i: number) => (
              <div key={i} className="cyber-timeline-item high mb-3">
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-2 rounded-full bg-cyber-orange animate-pulse" />
                  <span className="text-xs font-mono text-cyber-textMuted">{flap.time}</span>
                </div>
                <div className="text-sm font-medium">WAN interface {flap.interface} flapped</div>
                <div className="text-xs text-cyber-textMuted mt-0.5 font-mono">Duration: {flap.duration}s</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}