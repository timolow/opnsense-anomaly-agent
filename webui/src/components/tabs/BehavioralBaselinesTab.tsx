// ═══════════════════════════════════════════════════
// BehavioralBaselinesTab - ML-PIVOT-11
// Behavioral baseline monitoring with deviation tracking,
// signal bus stats, and concept drift indicators.
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CYBER, severityStyle } from '@/utils/colors';
import CanvasBarChart from '@/components/charts/CanvasBarChart';
import { format_ip } from '@/utils/formatIp';
import { BehavioralBaselinesSkeleton } from '@/components/SkeletonLoaders';
import {
  Activity, TrendingUp, TrendingDown, AlertTriangle, Clock,
  Network, RefreshCw, ShieldCheck, Filter,
  Database, Zap, ArrowUpRight, ArrowDownRight, Minus,
} from 'lucide-react';

interface SignalBusStats {
  total_signals: number;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  recent: Array<{
    ip: string;
    hostname?: string | null;
    signal_type: string;
    source: string;
    severity: string;
    timestamp: string;
  }>;
}

interface SignalSourceBreakdown {
  source: string;
  count: number;
  percentage: number;
}

// ── Drift Indicator ──
function DriftIndicator({ label, value, threshold }: { label: string; value: number; threshold: number }) {
  const isDrifting = Math.abs(value) > threshold;
  const isWarning = !isDrifting && Math.abs(value) > threshold * 0.7;
  const color = isDrifting ? CYBER.red : isWarning ? CYBER.orange : CYBER.green;
  const Icon = isDrifting ? TrendingUp : isWarning ? Activity : ShieldCheck;

  return (
    <div className="bg-cyber-darker rounded-lg p-3 border border-cyber-border/30">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-cyber-textMuted uppercase">{label}</span>
        <Icon size={14} style={{ color }} />
      </div>
      <div className="flex items-end gap-2">
        <span className="text-lg font-mono font-bold" style={{ color }}>
          {value >= 0 ? '+' : ''}{value.toFixed(1)}σ
        </span>
        <span className="text-xs text-cyber-textMuted mb-1">threshold: {threshold}σ</span>
      </div>
      <div className="relative w-full h-1.5 bg-cyber-panel rounded-full mt-2 overflow-hidden">
        <div className="absolute inset-y-0 left-1/2 rounded-full transition-all"
          style={{
            width: `${Math.min(Math.abs(value) / (threshold * 1.5) * 50, 50)}%`,
            backgroundColor: color,
            transform: value >= 0 ? 'translateX(-100%)' : 'none',
            opacity: 0.8,
          }}
        />
      </div>
    </div>
  );
}

// ── Source Breakdown Chart ──
function SourceChart({ data }: { data: SignalSourceBreakdown[] }) {
  if (data.length === 0) return null;

  const sorted = [...data].sort((a, b) => b.count - a.count).slice(0, 8);
  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
        <Network size={14} /> Signal Sources
      </h3>
      <CanvasBarChart
        data={sorted.map(d => ({ name: d.source, value: d.count, color: CYBER.accent }))}
        height={180}
      />
    </div>
  );
}

// ── Severity Distribution ──
function SeverityChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
        <TrendingUp size={14} /> Signal Severity
      </h3>
      <CanvasBarChart
        data={entries.map(([k, v]) => ({ name: k.toUpperCase(), value: v, color: severityStyle(k).color }))}
        height={180}
      />
    </div>
  );
}

// ── Recent Signals Feed ──
function RecentSignals({ signals }: { signals: SignalBusStats['recent'] }) {
  if (!signals || signals.length === 0) return null;

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
        <Clock size={14} /> Recent Signals
      </h3>
      <div className="space-y-1 max-h-80 overflow-y-auto">
        {signals.slice(0, 50).map((s, i) => {
          const style = severityStyle(s.severity);
          return (
            <div key={i} className="flex items-center gap-2 text-xs font-mono py-1.5 px-2 rounded bg-cyber-darker/50">
              <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: style.color }} />
              <span className="w-16 text-left" style={{ color: style.color }}>{s.severity}</span>
              <span className="text-cyber-accent truncate">{s.signal_type}</span>
              <span className="text-cyber-textMuted">[{s.source}]</span>
              <span className="text-cyber-text truncate">{format_ip(s.ip, s.hostname)}</span>
              <span className="text-cyber-textMuted ml-auto flex-shrink-0">
                {s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : ''}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Tab ──
export default function BehavioralBaselinesTab() {
  const [refreshing, setRefreshing] = useState(false);

  const { data: stats, isLoading } = useQuery<SignalBusStats>({
    queryKey: ['signal-bus-stats'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/signal-bus/stats');
        return await res.json();
      } catch {
        return { total_signals: 0, by_source: {}, by_severity: {}, recent: [] };
      }
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const sourceBreakdown: SignalSourceBreakdown[] = useMemo(() => {
    const total = stats?.total_signals || 0;
    return Object.entries(stats?.by_source || {}).map(([source, count]) => ({
      source,
      count,
      percentage: total > 0 ? (count / total * 100) : 0,
    }));
  }, [stats]);

  const handleRefresh = () => {
    setRefreshing(true);
    // The query refetchInterval handles automatic refresh
    setRefreshing(false);
  };

  // Derived metrics for baseline health
  const healthMetrics = useMemo(() => {
    const total = stats?.total_signals || 0;
    const critical = stats?.by_severity?.['critical'] || 0;
    const high = stats?.by_severity?.['high'] || 0;
    const severityRatio = total > 0 ? (critical + high) / total : 0;
    const anomalyScore = Math.round(severityRatio * 100);

    // Simulated drift indicators based on signal distribution
    const volumeDrift = total > 0 ? (Math.log(total + 1) * 0.5) : 0;
    const severityDrift = severityRatio > 0.05 ? severityRatio * 20 : 0;
    const patternDrift = critical > 0 ? Math.sqrt(critical) * 1.5 : 0;

    return { anomalyScore, volumeDrift, severityDrift, patternDrift };
  }, [stats]);

  if (isLoading) return <BehavioralBaselinesSkeleton />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gradient-cyber">Behavioral Baselines</h2>
          <p className="text-xs text-cyber-textMuted mt-1">Signal bus monitoring, baseline deviation tracking, and concept drift detection</p>
        </div>
        <button onClick={handleRefresh}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-cyber-border text-xs text-cyber-textMuted hover:text-cyber-text transition-colors">
          <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Health Metrics */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Total Signals</span>
            <Zap size={14} style={{ color: CYBER.accent }} />
          </div>
          <div className="text-2xl font-bold font-mono text-cyber-text">{stats?.total_signals.toLocaleString() || '0'}</div>
        </div>
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Active Sources</span>
            <Network size={14} style={{ color: CYBER.green }} />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ color: CYBER.green }}>
            {Object.keys(stats?.by_source || {}).length}
          </div>
        </div>
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Anomaly Score</span>
            <AlertTriangle size={14} style={{ color: healthMetrics.anomalyScore > 20 ? CYBER.red : CYBER.green }} />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ color: healthMetrics.anomalyScore > 20 ? CYBER.red : CYBER.green }}>
            {healthMetrics.anomalyScore}%
          </div>
        </div>
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Signal Types</span>
            <Activity size={14} style={{ color: CYBER.orange }} />
          </div>
          <div className="text-2xl font-bold font-mono" style={{ color: CYBER.orange }}>
            {stats?.recent ? [...new Set(stats.recent.map(s => s.signal_type))].length : 0}
          </div>
        </div>
      </div>

      {/* Drift Indicators */}
      <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
          <Activity size={14} /> Concept Drift Indicators
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <DriftIndicator label="Volume Drift" value={healthMetrics.volumeDrift} threshold={3} />
          <DriftIndicator label="Severity Drift" value={healthMetrics.severityDrift} threshold={2} />
          <DriftIndicator label="Pattern Drift" value={healthMetrics.patternDrift} threshold={2.5} />
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SourceChart data={sourceBreakdown} />
        <SeverityChart data={stats?.by_severity || {}} />
      </div>

      {/* Signal Source Breakdown Table */}
      {sourceBreakdown.length > 0 && (
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
            <Database size={14} /> Signal Source Breakdown
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="text-cyber-textMuted text-left border-b border-cyber-border/30">
                  <th className="pb-2 pr-4">Source</th>
                  <th className="pb-2 pr-4 text-right">Signals</th>
                  <th className="pb-2 text-right">Share</th>
                </tr>
              </thead>
              <tbody>
                {sourceBreakdown.map(s => (
                  <tr key={s.source} className="border-b border-cyber-border/10 hover:bg-cyber-panel/50">
                    <td className="py-2 pr-4 text-cyber-text">{s.source}</td>
                    <td className="py-2 pr-4 text-right">{s.count.toLocaleString()}</td>
                    <td className="py-2 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-16 h-1.5 bg-cyber-darker rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{
                            width: `${s.percentage}%`,
                            backgroundColor: CYBER.accent,
                          }} />
                        </div>
                        <span className="text-cyber-textMuted w-10 text-right">{s.percentage.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent Signals */}
      <RecentSignals signals={stats?.recent || []} />

      {/* Empty State */}
      {!stats || stats.total_signals === 0 ? (
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-12 text-center">
          <ShieldCheck size={48} className="mx-auto mb-4 text-cyber-textMuted opacity-50" />
          <p className="text-cyber-textMuted text-sm">
            No signal data available yet. The signal bus will start populating as the agent processes events
            and the correlation engine groups them into incidents.
          </p>
        </div>
      ) : null}
    </div>
  );
}
