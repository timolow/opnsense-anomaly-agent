// ═══════════════════════════════════════════════════
// Overview Tab - Main dashboard with stats, threats, timeline
// ═══════════════════════════════════════════════════

import { useEffect, useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { StatsData, AlertsData, BaselineDeviationsData, SparklinePoint, WhatChangedData } from '@/types';
import {
  AlertTriangle, Shield, Ban, Eye, TrendingUp,
  Activity, Clock, ArrowUpRight, ArrowDownRight,
  BarChart3, Zap, ChevronDown, ChevronUp,
  RadioTower, Network, ShieldCheck, Bell, FileText, Volume2,
  RefreshCw, X, Shield, Lock,
} from 'lucide-react';
import CanvasBarChart from '../../components/charts/CanvasBarChart';
import TimelineChart from '../../components/charts/TimelineChart';
import Sparkline from '../../components/charts/Sparkline';
import CanvasAreaChart from '../../components/charts/CanvasAreaChart';
import { format_ip } from '@/utils/formatIp';
import { useStore } from '../../store';
import { CYBER, SEVERITY, RECHARTS_TOOLTIP } from '@/utils/colors';
import { OverviewSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

// ── Traffic Summary: consolidated panel ──

function MiniSparkline({ data }: { data: { time: number; value: number }[] }) {
  if (!data || data.length === 0) {
    return <div className="h-[64px] flex items-center justify-center text-xs text-cyber-textMuted">No timeline data</div>;
  }
  const chartData = data.map((d, i) => ({ x: i, value: d.value }));
  return <CanvasAreaChart data={chartData} height={64} color="#00ffd5" />;
}

function PassBlockBar({ passed, blocked }: { passed: number; blocked: number }) {
  const total = passed + blocked;
  if (total === 0) return null;
  const passPct = Math.round((passed / total) * 100);
  const blockPct = 100 - passPct;
  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-mono text-cyber-textMuted">Pass / Block ratio</span>
        <span className="text-xs font-mono font-bold" style={{ color: '#00ffd5' }}>{passPct}% / {blockPct}%</span>
      </div>
      <div className="h-3 w-full rounded-full overflow-hidden flex" style={{ background: 'rgba(255,255,255,0.04)' }}>
        <div
          className="h-full transition-all duration-500"
          style={{ width: `${passPct}%`, background: 'linear-gradient(90deg, #00ff88, #00ffd5)' }}
        />
        <div
          className="h-full transition-all duration-500"
          style={{ width: `${blockPct}%`, background: 'linear-gradient(90deg, #ff1744, #ff5252)' }}
        />
      </div>
      <div className="flex justify-between mt-1">
        <span className="text-[10px] font-mono" style={{ color: '#00ff88' }}>Passed {passed.toLocaleString()}</span>
        <span className="text-[10px] font-mono" style={{ color: '#ff1744' }}>Blocked {blocked.toLocaleString()}</span>
      </div>
    </div>
  );
}

function TrafficSummary({ stats, timelineData }: { stats: StatsData; timelineData: { time: number; value: number }[] }) {
  const sparkEvents = stats.sparklines?.events;
  const sparkBlocked = stats.sparklines?.blocked;
  const sparkPassed = stats.sparklines?.passed;
  const sparkIps = stats.sparklines?.unique_ips;

  return (
    <div className="cyber-card p-5">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <RadioTower size={14} /> Traffic Summary
      </h3>

      {/* Top section: large events number + sparkline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-5">
        <div className="lg:col-span-1 flex flex-col justify-center">
          <div className="text-4xl font-bold font-mono text-cyber-accent">
            {(stats.events_24h || 0).toLocaleString()}
          </div>
          <div className="text-sm text-cyber-textMuted mt-1">Total Events (24h)</div>
          {sparkEvents && sparkEvents.length > 1 && (
            <Sparkline data={sparkEvents} color="#00ffd5" height={36} width={140} />
          )}
        </div>
        <div className="lg:col-span-2">
          <MiniSparkline data={timelineData} />
        </div>
      </div>

      {/* Middle: inline mini stats row with sparklines */}
      <div className="grid grid-cols-3 gap-3 mb-5">
        <div className="rounded-lg p-3 text-center" style={{ background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.2)' }}>
          <Ban size={16} className="mx-auto mb-1" style={{ color: '#ff1744' }} />
          <div className="text-xl font-bold font-mono" style={{ color: '#ff1744' }}>{(stats.blocked_24h || 0).toLocaleString()}</div>
          <div className="text-[10px] uppercase tracking-wider text-cyber-textMuted mt-0.5">Blocked</div>
          {sparkBlocked && sparkBlocked.length > 1 && (
            <Sparkline data={sparkBlocked} color="#ff1744" height={28} width="100%" />
          )}
        </div>
        <div className="rounded-lg p-3 text-center" style={{ background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.2)' }}>
          <ShieldCheck size={16} className="mx-auto mb-1" style={{ color: '#00ff88' }} />
          <div className="text-xl font-bold font-mono" style={{ color: '#00ff88' }}>{(stats.passed_24h || 0).toLocaleString()}</div>
          <div className="text-[10px] uppercase tracking-wider text-cyber-textMuted mt-0.5">Passed</div>
          {sparkPassed && sparkPassed.length > 1 && (
            <Sparkline data={sparkPassed} color="#00ff88" height={28} width="100%" />
          )}
        </div>
        <div className="rounded-lg p-3 text-center" style={{ background: 'rgba(100,116,139,0.08)', border: '1px solid rgba(100,116,139,0.2)' }}>
          <Network size={16} className="mx-auto mb-1" style={{ color: '#94a3b8' }} />
          <div className="text-xl font-bold font-mono text-cyber-accent">{stats.unique_ips?.toLocaleString() || '0'}</div>
          <div className="text-[10px] uppercase tracking-wider text-cyber-textMuted mt-0.5">Unique IPs</div>
          {sparkIps && sparkIps.length > 1 && (
            <Sparkline data={sparkIps} color="#06b6d4" height={28} width="100%" />
          )}
        </div>
      </div>

      {/* Bottom: Pass/Block ratio bar */}
      <PassBlockBar passed={stats.passed_24h || 0} blocked={stats.blocked_24h || 0} />
    </div>
  );
}

// ── Collapsible Agent Status ──

const AGENT_STATUS_ICONS: Record<string, React.ComponentType<{ size: number }>> = {
  'Anomalies': AlertTriangle,
  'Alerts Sent': Bell,
  'Rules Classified': FileText,
  'Active Mutes': Volume2,
};

const AGENT_STATUS_COLORS: Record<string, string> = {
  'Anomalies': '#ffbe0b',
  'Alerts Sent': '#00ffd5',
  'Rules Classified': '#a855f7',
  'Active Mutes': '#94a3b8',
};

function AgentStatus({ stats }: { stats: StatsData }) {
  const [collapsed, setCollapsed] = useState(false);
  const sparkAnomalies = stats.sparklines?.anomalies;

  const items = [
    { label: 'Anomalies', value: stats.anomalies_detected },
    { label: 'Alerts Sent', value: stats.alerts_sent },
    { label: 'Rules Classified', value: stats.rules_classified },
    { label: 'Active Mutes', value: stats.mutes_active },
  ];

  return (
    <div className="cyber-card overflow-hidden">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between p-4 cursor-pointer transition-colors hover:bg-white/5"
      >
        <span className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider flex items-center gap-2">
          <Activity size={14} /> Agent Status
        </span>
        {collapsed ? <ChevronDown size={16} className="text-cyber-textMuted" /> : <ChevronUp size={16} className="text-cyber-textMuted" />}
      </button>
      {!collapsed && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 px-4 pb-4">
          {items.map((item) => {
            const Icon = AGENT_STATUS_ICONS[item.label] || Activity;
            const color = AGENT_STATUS_COLORS[item.label] || '#e2e8f0';
            const showSpark = item.label === 'Anomalies' && sparkAnomalies && sparkAnomalies.length > 1;
            return (
              <div key={item.label} className="rounded-lg p-3 text-center" style={{ background: `${color}10`, border: `1px solid ${color}30` }}>
                <Icon size={16} className="mx-auto mb-1" style={{ color }} />
                <div className="text-xl font-bold font-mono" style={{ color }}>{item.value.toLocaleString()}</div>
                <div className="text-[10px] uppercase tracking-wider text-cyber-textMuted mt-0.5">{item.label}</div>
                {showSpark && (
                  <Sparkline data={sparkAnomalies} color={color} height={24} width="100%" />
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ThreatSummary({ data }: { data: StatsData }) {
  const setActiveTab = useStore((s) => s.setActiveTab);
  const setFilterSeverity = useStore((s) => s.setFilterSeverity);

  const threats = [
    { label: 'CRITICAL', value: data.threat_critical, color: 'text-cyber-red', border: 'border-cyber-red', bg: 'rgba(255,23,68,0.1)', sev: 'CRITICAL' as const },
    { label: 'HIGH', value: data.threat_high, color: 'text-cyber-orange', border: 'border-cyber-orange', bg: 'rgba(255,120,0,0.1)', sev: 'HIGH' as const },
    { label: 'MEDIUM', value: data.threat_medium, color: 'text-cyber-yellow', border: 'border-cyber-yellow', bg: 'rgba(255,190,11,0.1)', sev: 'MEDIUM' as const },
    { label: 'LOW', value: data.threat_low, color: 'text-cyber-green', border: 'border-cyber-green', bg: 'rgba(0,255,136,0.1)', sev: 'LOW' as const },
  ];

  const handleClick = (sev: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') => {
    setFilterSeverity(sev);
    setActiveTab('alerts');
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      {threats.map((t) => (
        <div
          key={t.label}
          className="cyber-card p-4 cyber-card-hover cursor-pointer group"
          onClick={() => handleClick(t.sev)}
          style={{ borderLeft: `3px solid var(--color-${t.label.toLowerCase()})` }}
        >
          <div className={`text-2xl font-bold font-mono ${t.color}`}>
            {t.value}
          </div>
          <div className="text-xs font-semibold uppercase tracking-wider text-cyber-textMuted mt-1">{t.label}</div>
        </div>
      ))}
    </div>
  );
}

function SeverityChart({ data }: { data: StatsData }) {
  const chartData = [
    { name: 'Critical', value: data.threat_critical, color: CYBER.red },
    { name: 'High', value: data.threat_high, color: CYBER.orange },
    { name: 'Medium', value: data.threat_medium, color: CYBER.yellow },
    { name: 'Low', value: data.threat_low, color: CYBER.green },
  ];

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <TrendingUp size={14} /> Severity Distribution
      </h3>
      <CanvasBarChart data={chartData} height={200} barSize={24} />
    </div>
  );
}

function BaselineDeviationsPanel({ data }: { data: BaselineDeviationsData }) {
  const setActiveTab = useStore((s) => s.setActiveTab);

  const severityStyle = (sev: string) => {
    switch (sev) {
      case 'critical': return { color: CYBER.red, bg: 'rgba(255,23,68,0.12)', border: 'var(--color-cyber-red)', glow: 'rgba(255,23,68,0.4)' };
      case 'warning': return { color: CYBER.orange, bg: 'rgba(255,120,0,0.12)', border: 'var(--color-cyber-orange)', glow: 'rgba(255,120,0,0.4)' };
      default: return { color: CYBER.yellow, bg: 'rgba(255,190,11,0.12)', border: 'var(--color-cyber-yellow)', glow: 'rgba(255,190,11,0.4)' };
    }
  };

  const handleClick = (rule: string) => {
    setActiveTab('rules-classified');
  };

  if (!data.deviations || data.deviations.length === 0) {
    return (
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <BarChart3 size={14} /> Baseline Deviations
        </h3>
        <div className="text-sm text-cyber-textMuted text-center py-8 font-mono">
          No rules currently exceeding their baseline thresholds
        </div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Zap size={14} /> Baseline Deviations
        <span className="text-xs font-mono text-cyber-textMuted ml-auto">
          {data.deviations.length} of {data.total_rules_with_baseline} rules
        </span>
      </h3>
      <div className="cyber-scrollable max-h-[360px] overflow-y-auto space-y-2">
        {data.deviations.map((d, i) => {
          const style = severityStyle(d.severity);
          return (
            <div
              key={i}
              className="cyber-card p-3 cyber-card-hover cursor-pointer group"
              onClick={() => handleClick(d.rule)}
              style={{ borderLeft: `3px solid ${style.border}`, background: style.bg }}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium truncate max-w-[60%] group-hover:text-cyber-accent transition-colors">
                  {d.rule_name || d.rule}
                </span>
                <span
                  className="text-lg font-bold font-mono"
                  style={{ color: style.color }}
                >
                  {d.deviation}x
                </span>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono text-cyber-textMuted">
                <span>Current: <span style={{ color: CYBER.text }}>{d.current_rate}/h</span></span>
                <span>Baseline: <span style={{ color: CYBER.text }}>{d.baseline_rate}/h</span></span>
                <span>Peak: <span style={{ color: CYBER.text }}>{d.max_per_hour}/h</span></span>
                <span className="ml-auto">
                  Samples: <span style={{ color: CYBER.text }}>{d.sample_count}</span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ActivityFeed({ alerts }: { alerts: AlertsData }) {
  const recent = alerts.anomalies.slice(0, 8);
  
  const severityIcon = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return <div className="w-2.5 h-2.5 rounded-full bg-cyber-red animate-pulse" />;
      case 'HIGH': return <div className="w-2.5 h-2.5 rounded-full bg-cyber-orange animate-pulse" />;
      case 'MEDIUM': return <div className="w-2.5 h-2.5 rounded-full bg-cyber-yellow animate-pulse" />;
      default: return <div className="w-2.5 h-2.5 rounded-full bg-cyber-green animate-pulse" />;
    }
  };

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Clock size={14} /> Recent Activity
      </h3>
      <div className="cyber-timeline max-h-[300px] overflow-y-auto">
        {recent.length === 0 ? (
          <div className="text-sm text-cyber-textMuted text-center py-8">No recent activity</div>
        ) : (
          recent.map((alert, i) => (
            <div key={i} className={`cyber-timeline-item ${alert.severity.toLowerCase()} mb-3`}>
              <div className="flex items-center gap-2 mb-1">
                {severityIcon(alert.severity)}
                <span className="text-xs font-mono text-cyber-textMuted">{alert.timestamp}</span>
              </div>
              <div className="text-sm font-medium">{alert.type}</div>
              <div className="text-xs text-cyber-textMuted mt-0.5 font-mono">
                {format_ip(alert.source_ip, alert.src_hostname)} → {format_ip(alert.destination_ip, alert.dst_hostname)}
              </div>
              <div className="text-xs text-cyber-textMuted mt-0.5">{alert.details}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const LOCAL_STORAGE_KEY = 'soc_dashboard_last_viewed';

function WhatChangedPanel({ data, onDismiss }: { data: WhatChangedData; onDismiss: () => void }) {
  const [collapsed, setCollapsed] = useState(false);
  const totalItems = data.new_anomalies + data.new_unique_ips.length + data.new_rule_matches.length + data.new_baseline_breaches.length;

  if (!data.first_time && totalItems === 0 && data.new_events === 0 && data.new_blocked === 0) {
    return (
      <div className="cyber-card p-4 relative">
        <button onClick={onDismiss} className="absolute top-3 right-3 text-cyber-textMuted hover:text-cyber-accent transition-colors">
          <X size={14} />
        </button>
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-2 flex items-center gap-2">
          <RefreshCw size={14} /> What Changed
        </h3>
        <div className="text-sm text-cyber-green font-mono text-center py-4">
          Nothing new since you last checked.
        </div>
      </div>
    );
  }

  const formatTimeAgo = (hours: number | null) => {
    if (hours === null) return '';
    if (hours < 1) return `${Math.round(hours * 60)} min ago`;
    if (hours < 24) return `${hours.toFixed(1)} hours ago`;
    return `${(hours / 24).toFixed(1)} days ago`;
  };

  return (
    <div className="cyber-card p-4 relative">
      <button onClick={onDismiss} className="absolute top-3 right-3 text-cyber-textMuted hover:text-cyber-accent transition-colors">
        <X size={14} />
      </button>
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between mb-0"
      >
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider flex items-center gap-2">
          <RefreshCw size={14} className="animate-spin" style={{ animationDuration: '3s' }} /> What Changed
          {data.first_time && (
            <span className="text-xs bg-cyber-purple/20 text-cyber-purple px-2 py-0.5 rounded font-mono">FIRST VISIT</span>
          )}
        </h3>
        <span className="text-xs font-mono text-cyber-textMuted">
          {collapsed ? '▼' : '▲'} {data.first_time ? 'all time' : formatTimeAgo(data.hours_since)}
        </span>
      </button>

      {/* Long gap warning */}
      {data.hours_since !== null && data.hours_since >= 24 && !collapsed && (
        <div className="mt-3 px-3 py-2 rounded bg-cyber-orange/10 border border-cyber-orange/30 text-sm font-mono text-cyber-orange text-center">
          ⚠ You have not checked in for {data.hours_since.toFixed(1)} hours
        </div>
      )}

      {!collapsed && (
        <div className="space-y-4 mt-4">
          {/* Summary stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div className="bg-cyber-bg/50 rounded-lg p-3 text-center">
              <div className="text-xl font-bold font-mono text-cyber-accent">{data.new_events.toLocaleString()}</div>
              <div className="text-xs text-cyber-textMuted">New Events</div>
            </div>
            <div className="bg-cyber-bg/50 rounded-lg p-3 text-center">
              <div className="text-xl font-mono font-bold text-cyber-red">{data.new_blocked.toLocaleString()}</div>
              <div className="text-xs text-cyber-textMuted">New Blocked</div>
            </div>
            <div className="bg-cyber-bg/50 rounded-lg p-3 text-center">
              <div className="text-xl font-bold font-mono text-cyber-yellow">{data.new_anomalies}</div>
              <div className="text-xs text-cyber-textMuted">New Anomalies</div>
            </div>
            <div className="bg-cyber-bg/50 rounded-lg p-3 text-center">
              <div className="text-xl font-bold font-mono text-cyber-orange">{data.new_unique_ips.length}</div>
              <div className="text-xs text-cyber-textMuted">New Source IPs</div>
            </div>
          </div>

          {/* New Source IPs */}
          {data.new_unique_ips.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-orange uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Network size={12} /> New Source IPs — {data.new_unique_ips.length}
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {data.new_unique_ips.slice(0, 10).map((ip, i) => (
                  <span key={i} className="cyber-tag text-xs font-mono" style={{ borderColor: 'var(--color-cyber-orange)' }}>
                    {format_ip(ip.ip, ip.hostname)} <span className="text-cyber-textMuted">({ip.count})</span>
                  </span>
                ))}
                {data.new_unique_ips.length > 10 && (
                  <span className="text-xs text-cyber-textMuted font-mono">+{data.new_unique_ips.length - 10} more</span>
                )}
              </div>
            </div>
          )}

          {/* New Rule Matches */}
          {data.new_rule_matches.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-purple uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Lock size={12} /> New Rule Matches — {data.new_rule_matches.length}
              </h4>
              <div className="space-y-1">
                {data.new_rule_matches.slice(0, 5).map((r, i) => (
                  <div key={i} className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded bg-cyber-bg/30">
                    <span className="truncate mr-2 text-cyber-text">{r.rule}</span>
                    <span className="text-cyber-purple whitespace-nowrap">{r.count} hits</span>
                  </div>
                ))}
                {data.new_rule_matches.length > 5 && (
                  <div className="text-xs text-cyber-textMuted font-mono">+{data.new_rule_matches.length - 5} more rules</div>
                )}
              </div>
            </div>
          )}

          {/* Baseline Breaches */}
          {data.new_baseline_breaches.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-cyber-red uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Zap size={12} /> Baseline Breaches — {data.new_baseline_breaches.length}
              </h4>
              <div className="space-y-1">
                {data.new_baseline_breaches.map((b, i) => (
                  <div key={i} className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded bg-cyber-bg/30">
                    <span className="truncate mr-2 text-cyber-text">{b.rule_name || 'unknown'}</span>
                    <span className="text-cyber-red whitespace-nowrap">{b.deviation}x deviation</span>
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

export default function OverviewTab() {
  const { timeRange, customTimeRange } = useStore();
  const [timelineData, setTimelineData] = useState<{ time: number; value: number }[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(true);
  const [sseTimelineData, setSSETimelineData] = useState<{ time: number; value: number }[]>([]);
  const [whatChangedVisible, setWhatChangedVisible] = useState(true);
  const [whatChangedData, setWhatChangedData] = useState<WhatChangedData | null>(null);
  const [whatChangedLoading, setWhatChangedLoading] = useState(false);

  // Load last_viewed from localStorage and fetch what changed
  useEffect(() => {
    let cancelled = false;
    const lastViewed = localStorage.getItem(LOCAL_STORAGE_KEY);

    if (!lastViewed) {
      // First visit — mark all data as "new"
      if (!cancelled) {
        setWhatChangedData({
          since_ts: null,
          hours_since: null,
          new_events: 0,
          new_anomalies: 0,
          new_blocked: 0,
          new_unique_ips: [],
          new_rule_matches: [],
          new_baseline_breaches: [],
          first_time: true,
        });
        setWhatChangedVisible(true);
      }
      return;
    }

    const ts = parseInt(lastViewed, 10);
    if (isNaN(ts) || ts <= 0) return;

    // If less than 30 seconds since last visit, don't show panel
    const elapsed = (Date.now() - ts) / 1000;
    if (elapsed < 30) {
      if (!cancelled) setWhatChangedVisible(false);
      return;
    }

    // If more than 24 hours, still show but with a "long gap" message
    setWhatChangedLoading(true);
    api.newSince(ts).then((data) => {
      if (!cancelled) {
        setWhatChangedData(data);
        setWhatChangedVisible(true);
        setWhatChangedLoading(false);
      }
    }).catch(() => {
      if (!cancelled) setWhatChangedLoading(false);
    });

    return () => { cancelled = true; };
  }, []);

  // Save current timestamp to localStorage when dismissing or navigating away
  const handleDismissWhatChanged = () => {
    setWhatChangedVisible(false);
    localStorage.setItem(LOCAL_STORAGE_KEY, String(Date.now()));
  };

  // Save timestamp when navigating to another tab (on unmount)
  useEffect(() => {
    return () => {
      localStorage.setItem(LOCAL_STORAGE_KEY, String(Date.now()));
    };
  }, []);

  const { data: stats, isLoading: statsLoading, isError: statsError, error: statsErrorObj } = useQuery<StatsData>({
    queryKey: ['stats'],
    queryFn: api.stats,
  });
  const { data: alerts, isError: alertsError, error: alertsErrorObj } = useQuery<AlertsData>({
    queryKey: ['alerts'],
    queryFn: api.alerts,
  });
  const { data: baselines } = useQuery<BaselineDeviationsData>({
    queryKey: ['baseline-deviations'],
    queryFn: api.baselineDeviations,
    refetchInterval: 60_000, // refresh every 60s
  });

  // Fetch timeline data based on time range
  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      setTimelineLoading(true);
      setSSETimelineData([]); // Clear SSE data when time range changes
      try {
        let start: number;
        let end: number;
        let period: string;
        let granularity: string;

        if (timeRange === 'custom' && customTimeRange) {
          start = customTimeRange.start;
          end = customTimeRange.end;
          period = 'custom';
          granularity = 'hour';
        } else {
          const now = Math.floor(Date.now() / 1000);
          period = timeRange || '24h';
          granularity = (period === '7d' || period === '30d') ? 'day' : 'hour';
          switch (period) {
            case '1h': start = now - 3600; break;
            case '6h': start = now - 21600; break;
            case '24h': start = now - 86400; break;
            case '7d': start = now - 604800; break;
            case '30d': start = now - 2592000; break;
            default: start = now - 86400;
          }
          end = now;
        }

        const result = await api.timeline({ period, granularity, start, end });

        if (!cancelled && result.timeline) {
          const data = result.timeline
            .map((item) => {
              // Handle PG timestamp format "2026-06-17 16:00:00+00:00" (space instead of T)
              const isoStr = item.time.replace(' ', 'T');
              const ts = Math.floor(new Date(isoStr).getTime() / 1000);
              if (!Number.isFinite(ts) || !Number.isFinite(item.count)) return null;
              return { time: ts, value: item.count };
            })
            .filter(Boolean) as { time: number; value: number }[];
          setTimelineData(data);
        }
      } catch (error) {
        if (!cancelled) {
          console.error('Failed to fetch timeline data:', error);
        }
      } finally {
        if (!cancelled) {
          setTimelineLoading(false);
        }
      }
    };

    fetchData();
    return () => { cancelled = true; };
  }, [timeRange, customTimeRange]);

  // SSE live updates - connect to SSE stream and merge with existing data
  useEffect(() => {
    let eventSource: EventSource | null = null;
    let mounted = true;

    // Only connect SSE for short time ranges where live updates make sense
    if (timeRange === '1h' || timeRange === '6h') {
      eventSource = new EventSource('/api/sse');

      eventSource.onmessage = (event) => {
        if (!mounted) return;

        try {
          const message = JSON.parse(event.data);
          const timestamp = Math.floor(new Date(message.timestamp || Date.now()).getTime() / 1000);

          setSSETimelineData(prevData => {
            const newData = [...prevData];
            const existingIndex = newData.findIndex(d => d.time === timestamp);

            if (existingIndex >= 0) {
              newData[existingIndex] = {
                ...newData[existingIndex],
                value: newData[existingIndex].value + 1,
              };
            } else {
              newData.push({ time: timestamp, value: 1 });
              newData.sort((a, b) => a.time - b.time);
            }

            // Keep only recent data
            if (newData.length > 1000) {
              newData.splice(0, newData.length - 1000);
            }

            return newData;
          });
        } catch (error) {
          console.error('Failed to parse SSE message:', error);
        }
      };

      eventSource.onerror = (error) => {
        console.error('SSE connection error:', error);
      };
    }

    return () => {
      mounted = false;
      if (eventSource) {
        eventSource.close();
      }
    };
  }, [timeRange]);

  // Merge static data with SSE live data
  const combinedTimelineData = useMemo(() => {
    if (sseTimelineData.length === 0) {
      return timelineData;
    }

    // Create a map of all time buckets
    const dataMap = new Map<number, number>();

    // Add static data
    timelineData.forEach(d => {
      dataMap.set(d.time, d.value);
    });

    // Add/merge SSE data
    sseTimelineData.forEach(d => {
      const existing = dataMap.get(d.time) || 0;
      dataMap.set(d.time, existing + d.value);
    });

    // Convert back to array
    return Array.from(dataMap.entries())
      .map(([time, value]) => ({ time, value }))
      .sort((a, b) => a.time - b.time);
  }, [timelineData, sseTimelineData]);

  if (!stats) {
    return <OverviewSkeleton />;
  }

  if (statsError && statsErrorObj) {
    return <TabQueryError error={statsErrorObj} isError={statsError} onRetry={() => window.location.reload()} tabName="Overview" />;
  }

  return (
    <div className="space-y-6">
      {/* What Changed Panel */}
      {whatChangedVisible && whatChangedData && (
        <WhatChangedPanel data={whatChangedData} onDismiss={handleDismissWhatChanged} />
      )}
      {whatChangedVisible && whatChangedLoading && (
        <div className="cyber-card p-4 flex items-center gap-3">
          <RefreshCw size={16} className="animate-spin text-cyber-accent" />
          <span className="text-sm font-mono text-cyber-textMuted">Checking what changed...</span>
        </div>
      )}

      <ThreatSummary data={stats} />

      <TrafficSummary stats={stats} timelineData={combinedTimelineData} />

      <AgentStatus stats={stats} />

      {/* Timeline Chart - uPlot time series with SSE live updates */}
      <TimelineChart
        title="Event Timeline"
        data={combinedTimelineData}
        isLoading={timelineLoading}
        height={300}
        isLive={sseTimelineData.length > 0}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-1 lg:col-span-2">
          <SeverityChart data={stats} />
        </div>
        <ActivityFeed alerts={alerts || { anomalies: [] }} />
      </div>

      {/* Baseline Deviations panel */}
      <BaselineDeviationsPanel data={baselines || { deviations: [], total_rules_with_baseline: 0, timestamp: '' }} />
    </div>
  );
}
