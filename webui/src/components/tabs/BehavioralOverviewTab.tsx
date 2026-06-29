// ═══════════════════════════════════════════════════
// BehavioralOverviewTab - ML-PIVOT-07
// Behavioral overview with behavior scores, incident stats,
// timeline, IP breakdown, and behavioral changes.
// ═══════════════════════════════════════════════════

import { useMemo, useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { BehaviorOverviewData, IncidentStats } from '@/types';
import { CYBER, severityStyle } from '@/utils/colors';
import CanvasAreaChart from '@/components/charts/CanvasAreaChart';
import CanvasBarChart from '@/components/charts/CanvasBarChart';
import { BehavioralOverviewSkeleton } from '@/components/SkeletonLoaders';
import {
  Activity, AlertTriangle, Shield, ShieldCheck, ShieldAlert,
  Globe, Zap, Clock, ArrowUpRight, ArrowDownRight, Minus,
  Cpu, Database, BarChart3, RefreshCw, X, Layers,
} from 'lucide-react';

// ── Color helpers for behavior levels ──
const BEHAVIOR_COLORS: Record<string, { main: string; bg: string; border: string }> = {
  benign: { main: CYBER.green, bg: 'rgba(0,255,136,0.1)', border: CYBER.green },
  suspicious: { main: CYBER.orange, bg: 'rgba(255,120,0,0.1)', border: CYBER.orange },
  hostile: { main: CYBER.red, bg: 'rgba(255,23,68,0.1)', border: CYBER.red },
};

function behaviorColor(level: string): string {
  return (BEHAVIOR_COLORS[level] || BEHAVIOR_COLORS.benign).main;
}

// ── Key Metrics Row ──
function KeyMetricsRow({ data }: { data: BehaviorOverviewData }) {
  const metrics = [
    {
      label: 'Active IPs (24h)',
      value: data.active_ips_24h.toLocaleString(),
      icon: Globe,
      color: CYBER.accent,
    },
    {
      label: 'Active Incidents',
      value: String(data.incident_stats.active),
      icon: AlertTriangle,
      color: data.incident_stats.active > 0 ? CYBER.red : CYBER.green,
    },
    {
      label: 'Top Threat IPs',
      value: String(data.top_threat_ips.length),
      icon: ShieldAlert,
      color: data.top_threat_ips.length > 0 ? CYBER.orange : CYBER.green,
    },
    {
      label: 'Pipeline Health',
      value: data.pipeline_health.events_per_second > 0
        ? `${data.pipeline_health.events_per_second.toFixed(1)} e/s`
        : 'Idle',
      icon: Cpu,
      color: data.pipeline_health.db_connected ? CYBER.green : CYBER.red,
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      {metrics.map((m) => (
        <div key={m.label} className="cyber-card p-4">
          <div className="flex items-center gap-2 mb-2">
            <m.icon size={16} style={{ color: m.color }} />
            <span className="text-xs font-semibold uppercase tracking-wider text-cyber-textMuted">
              {m.label}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono" style={{ color: m.color }}>
            {m.value}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── IP Breakdown Donut ──
function IpBreakdown({ data }: { data: BehaviorOverviewData }) {
  const breakdown = data.ip_breakdown;
  const total = breakdown.total || 1;

  const chartData = [
    { name: 'Benign', value: breakdown.benign, color: CYBER.green },
    { name: 'Suspicious', value: breakdown.suspicious, color: CYBER.orange },
    { name: 'Hostile', value: breakdown.hostile, color: CYBER.red },
  ];

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Globe size={14} /> IP Behavior Breakdown
      </h3>
      <div className="flex items-center justify-around">
        {/* Donut-like bar chart */}
        <CanvasBarChart data={chartData} height={160} barSize={18} />
        <div className="space-y-2 text-sm font-mono">
          {chartData.map((d) => (
            <div key={d.name} className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: d.color }} />
              <span className="text-cyber-textMuted w-20">{d.name}</span>
              <span className="font-bold" style={{ color: d.color }}>
                {d.value.toLocaleString()}
              </span>
              <span className="text-cyber-textMuted">
                ({((d.value / total) * 100).toFixed(1)}%)
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Behavioral Timeline ──
function BehavioralTimeline({ data }: { data: BehaviorOverviewData }) {
  const timeline = data.behavior_timeline;

  if (!timeline || timeline.length === 0) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <BarChart3 size={14} /> Behavioral Timeline
        </h3>
        <div className="text-sm text-cyber-textMuted text-center py-8 font-mono">
          No behavioral timeline data available
        </div>
      </div>
    );
  }

  // Build stacked area chart data: [benign, suspicious, hostile]
  // CanvasAreaChart expects { x: number; value: number }
  const areaData: Array<{ x: number; value: number }> = timeline.map((pt, i) => ({
    x: i,
    value: pt.benign + pt.suspicious + pt.hostile,
  }));

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Activity size={14} /> Behavioral Timeline
        <span className="text-xs font-mono text-cyber-textMuted ml-auto">
          {timeline.length} points
        </span>
      </h3>
      <CanvasAreaChart
        data={areaData}
        height={200}
        color={CYBER.accent}
      />
      {/* Legend with behavior level breakdown */}
      <div className="flex items-center gap-4 mt-3 text-xs font-mono text-cyber-textMuted">
        {Object.entries(BEHAVIOR_COLORS).map(([level, colors]) => (
          <div key={level} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: colors.main }} />
            <span className="uppercase">{level}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Incident Stats Panel ──
function IncidentStatsPanel({ data }: { data: IncidentStats }) {
  const hasData = data.active > 0 || data.escalated_24h > 0 || data.recent.length > 0;

  if (!hasData) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <ShieldAlert size={14} /> Incident Stats
        </h3>
        <div className="text-sm text-cyber-textMuted text-center py-8 font-mono">
          No active incidents
        </div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <ShieldAlert size={14} /> Incident Stats
      </h3>
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="text-center">
          <div className="text-xl font-bold font-mono" style={{ color: CYBER.red }}>{data.active}</div>
          <div className="text-xs text-cyber-textMuted uppercase">Active</div>
        </div>
        <div className="text-center">
          <div className="text-xl font-bold font-mono" style={{ color: CYBER.orange }}>{data.escalated_24h}</div>
          <div className="text-xs text-cyber-textMuted uppercase">Escalated 24h</div>
        </div>
        <div className="text-center">
          <div className="text-xl font-bold font-mono" style={{ color: CYBER.green }}>{data.resolved_24h}</div>
          <div className="text-xs text-cyber-textMuted uppercase">Resolved 24h</div>
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="mb-4">
        <h4 className="text-xs font-semibold text-cyber-textMuted uppercase tracking-wider mb-2">
          By Severity
        </h4>
        <div className="grid grid-cols-4 gap-2">
          {Object.entries(data.by_severity).map(([sev, count]: [string, number]) => {
            const style = severityStyle(sev.toUpperCase());
            return (
              <div key={sev} className="text-center rounded-lg p-2" style={{ background: style.bg }}>
                <div className="text-lg font-bold font-mono" style={{ color: style.color }}>
                  {count}
                </div>
                <div className="text-[10px] uppercase text-cyber-textMuted">{sev}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent incidents */}
      {data.recent.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-cyber-textMuted uppercase tracking-wider mb-2">
            Recent Incidents
          </h4>
          <div className="cyber-scrollable max-h-[200px] overflow-y-auto space-y-2">
            {data.recent.slice(0, 8).map((inc) => {
              const style = severityStyle(inc.severity);
              return (
                <div
                  key={inc.id}
                  className="p-2 rounded-lg"
                  style={{ background: style.bg, borderLeft: `3px solid ${style.border}` }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium truncate max-w-[60%]">
                      {inc.description}
                    </span>
                    <span className="text-xs font-mono" style={{ color: style.color }}>
                      {inc.severity}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-cyber-textMuted">
                    {inc.source_ip} &middot; {inc.timestamp}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Top Threat IPs ──
function TopThreatIps({ data }: { data: BehaviorOverviewData }) {
  const ips = data.top_threat_ips;

  if (!ips || ips.length === 0) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <ShieldAlert size={14} /> Top Threat IPs
        </h3>
        <div className="text-sm text-cyber-textMuted text-center py-8 font-mono">
          No threat IPs detected
        </div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <ShieldAlert size={14} /> Top Threat IPs
      </h3>
      <div className="cyber-scrollable max-h-[240px] overflow-y-auto space-y-2">
        {ips.slice(0, 10).map((ipData, i) => {
          const color = behaviorColor(ipData.level);
          return (
            <div
              key={ipData.ip}
              className="flex items-center justify-between p-2 rounded-lg"
              style={{ background: `${color}10`, borderLeft: `3px solid ${color}` }}
            >
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-cyber-textMuted w-4">{i + 1}</span>
                <span className="text-sm font-mono">{ipData.ip}</span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="text-cyber-textMuted">{ipData.events} events</span>
                <span className="font-bold" style={{ color }}>
                  {ipData.score}/100
                </span>
                <span className="uppercase" style={{ color }}>
                  {ipData.level}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── What Changed (Behavioral) ──
function BehavioralChangesPanel({ data }: { data: BehaviorOverviewData }) {
  const [collapsed, setCollapsed] = useState(false);
  const changes = data.behavioral_changes;
  const hasChanges =
    changes.new_suspicious_ips.length > 0 ||
    changes.escalated_incidents.length > 0 ||
    changes.resolved_threats.length > 0;

  if (!hasChanges) {
    return (
      <div className="cyber-card p-4">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="w-full flex items-center justify-between"
        >
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider flex items-center gap-2">
            <RefreshCw size={14} /> Behavioral Changes
          </h3>
          <span className="text-xs font-mono text-cyber-textMuted">
            {collapsed ? '▼' : '▲'} All clear
          </span>
        </button>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between"
      >
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider flex items-center gap-2">
          <RefreshCw size={14} className="animate-spin" style={{ animationDuration: '3s' }} />
          Behavioral Changes
        </h3>
        <span className="text-xs font-mono text-cyber-textMuted">
          {collapsed ? '▼' : '▲'}{' '}
          {changes.new_suspicious_ips.length + changes.escalated_incidents.length + changes.resolved_threats.length} changes
        </span>
      </button>

      {!collapsed && (
        <div className="space-y-4 mt-4">
          {/* New Suspicious IPs */}
          {changes.new_suspicious_ips.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-orange uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Globe size={12} /> New Suspicious IPs — {changes.new_suspicious_ips.length}
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {changes.new_suspicious_ips.slice(0, 10).map((ip, i) => (
                  <span key={i} className="cyber-tag text-xs font-mono" style={{ borderColor: CYBER.orange }}>
                    {ip.ip} <span className="text-cyber-textMuted">(score: {ip.score})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Escalated Incidents */}
          {changes.escalated_incidents.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-red uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <AlertTriangle size={12} /> Escalated Incidents — {changes.escalated_incidents.length}
              </h4>
              <div className="space-y-1">
                {changes.escalated_incidents.map((inc, i) => (
                  <div key={i} className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded bg-cyber-bg/30">
                    <span className="truncate mr-2">{inc.type}</span>
                    <span className="text-cyber-red uppercase whitespace-nowrap">{inc.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Resolved Threats */}
          {changes.resolved_threats.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-green uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <ShieldCheck size={12} /> Resolved Threats — {changes.resolved_threats.length}
              </h4>
              <div className="space-y-1">
                {changes.resolved_threats.slice(0, 5).map((t, i) => (
                  <div key={i} className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded bg-cyber-bg/30">
                    <span className="truncate mr-2">{t.type}</span>
                    <span className="text-cyber-green whitespace-nowrap">{t.timestamp}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Traffic Flow with Behavioral Classification ──
function TrafficFlowBehavioral({ data }: { data: BehaviorOverviewData }) {
  const flows = data.traffic_flows;

  if (!flows || flows.length === 0) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <Layers size={14} /> Traffic Flow Behavior
        </h3>
        <div className="text-sm text-cyber-textMuted text-center py-8 font-mono">
          No behavioral flow data available yet
        </div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Layers size={14} /> Traffic Flow Behavior
      </h3>
      <div className="cyber-scrollable max-h-[240px] overflow-y-auto space-y-2">
        {flows.map((flow, i) => {
          const color = behaviorColor(flow.behavior_level);
          return (
            <div
              key={i}
              className="flex items-center justify-between p-2 rounded-lg"
              style={{ background: `${color}10`, borderLeft: `3px solid ${color}` }}
            >
              <div className="text-xs font-mono">
                <span className="text-cyber-accent">{flow.src_category}</span>
                <span className="text-cyber-textMuted mx-2">→</span>
                <span className="text-cyber-accent">{flow.dst_category}</span>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="text-cyber-textMuted">{flow.event_count} events</span>
                <span className="uppercase font-bold" style={{ color }}>
                  {flow.behavior_level}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Pipeline Health ──
function PipelineHealth({ health }: { health: BehaviorOverviewData['pipeline_health'] }) {
  const isHealthy = health.db_connected && health.events_per_second > 0;

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Cpu size={14} /> Pipeline Health
      </h3>
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg p-3 text-center" style={{ background: `${CYBER.green}10`, border: `1px solid ${CYBER.green}30` }}>
          <div className="text-lg font-bold font-mono" style={{ color: health.events_per_second > 0 ? CYBER.green : CYBER.textMuted }}>
            {health.events_per_second.toFixed(1)}
          </div>
          <div className="text-[10px] uppercase text-cyber-textMuted">Events/sec</div>
        </div>
        <div className="rounded-lg p-3 text-center" style={{ background: `${health.db_connected ? CYBER.green : CYBER.red}10`, border: `1px solid ${health.db_connected ? CYBER.green : CYBER.red}30` }}>
          <div className="text-lg font-bold font-mono" style={{ color: health.db_connected ? CYBER.green : CYBER.red }}>
            {health.db_connected ? '✓' : '✗'}
          </div>
          <div className="text-[10px] uppercase text-cyber-textMuted">DB Status</div>
        </div>
        <div className="rounded-lg p-3 text-center col-span-2" style={{ background: `${CYBER.accent}10`, border: `1px solid ${CYBER.accent}30` }}>
          <div className="text-sm font-mono" style={{ color: CYBER.accent }}>
            {health.last_event}
          </div>
          <div className="text-[10px] uppercase text-cyber-textMuted">Last Event</div>
        </div>
        <div className="rounded-lg p-3 text-center col-span-2" style={{ background: `${CYBER.accent}10`, border: `1px solid ${CYBER.accent}30` }}>
          <div className="text-lg font-bold font-mono" style={{ color: CYBER.accent }}>
            {(health.anomaly_rate * 100).toFixed(2)}%
          </div>
          <div className="text-[10px] uppercase text-cyber-textMuted">Anomaly Rate</div>
        </div>
      </div>
    </div>
  );
}

// ── Data Source Warning ──
function DataSourceWarning({ status, message }: { status: string; message: string }) {
  if (status === 'configured') return null;

  return (
    <div className="cyber-card p-3" style={{ background: `${CYBER.orange}08`, border: `1px solid ${CYBER.orange}30` }}>
      <div className="flex items-center gap-2 text-xs font-mono text-cyber-orange">
        <AlertTriangle size={14} />
        <span>{message || 'ML behavioral analysis endpoint not available — showing derived data'}</span>
      </div>
    </div>
  );
}

// ── Main Tab ──
export default function BehavioralOverviewTab() {
  const { data, isLoading, isError, error } = useQuery<BehaviorOverviewData>({
    queryKey: ['behavior-overview'],
    queryFn: api.behaviorOverview,
    refetchInterval: 30_000,
  });

  if (isLoading) {
    return <BehavioralOverviewSkeleton />;
  }

  if (isError || !data) {
    return (
      <div className="cyber-card p-8 text-center">
        <AlertTriangle size={32} className="mx-auto mb-3 text-cyber-red" />
        <h3 className="text-lg font-semibold text-cyber-text mb-2">Failed to load behavioral data</h3>
        <p className="text-sm text-cyber-textMuted font-mono">
          {error instanceof Error ? error.message : 'Unknown error'}
        </p>
        <button
          onClick={() => window.location.reload()}
          className="mt-4 px-4 py-2 rounded-lg text-sm font-mono text-cyber-accent border border-cyber-accent/30 hover:bg-cyber-accent/10 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Data source warning */}
      <DataSourceWarning status={data.data_source_status || 'configured'} message={data.empty_message || ''} />

      {/* Key Metrics */}
      <KeyMetricsRow data={data} />

      {/* Behavioral Changes */}
      <BehavioralChangesPanel data={data} />

      {/* Timeline + IP Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <BehavioralTimeline data={data} />
        </div>
        <IpBreakdown data={data} />
      </div>

      {/* Incidents + Top Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <IncidentStatsPanel data={data.incident_stats} />
        <TopThreatIps data={data} />
      </div>

      {/* Pipeline Health + Traffic Flows */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <PipelineHealth health={data.pipeline_health} />
        <TrafficFlowBehavioral data={data} />
      </div>
    </div>
  );
}
