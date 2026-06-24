// ═══════════════════════════════════════════════════
// Overview Tab - Main dashboard with stats, threats, timeline
// ═══════════════════════════════════════════════════

import { useEffect, useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { StatsData, AlertsData } from '@/types';
import {
  AlertTriangle, Shield, Ban, Eye, TrendingUp,
  Activity, Clock, ArrowUpRight, ArrowDownRight,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useStore } from '../../store';
import TimelineChart from '../../components/charts/TimelineChart';
import { QueryErrorState } from '../TabErrorBoundary';
import { TabQueryWrapper } from '../../components/TabQueryWrapper';

function StatBox({ value, label, color, change }: {
  value: string | number;
  label: string;
  color?: string;
  change?: { value: number; positive: boolean };
}) {
  return (
    <div className="cyber-card p-4 cyber-card-hover group">
      <div className="flex items-start justify-between mb-2">
        <span className="cyber-stat-label">{label}</span>
        {change && (
          <span className={`flex items-center gap-0.5 text-xs font-mono ${change.positive ? 'text-cyber-green' : 'text-cyber-red'}`}>
            {change.positive ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
            {change.value}%
          </span>
        )}
      </div>
      <div className={`text-2xl font-bold font-mono ${color || 'text-neon-cyan'}`} style={color ? { textShadow: `0 0 20px ${color}` } : undefined}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

function ThreatSummary({ data }: { data: StatsData }) {
  const threats = [
    { label: 'CRITICAL', value: data.threat_critical, color: 'text-cyber-red', border: 'border-cyber-red', bg: 'rgba(255,23,68,0.1)' },
    { label: 'HIGH', value: data.threat_high, color: 'text-cyber-orange', border: 'border-cyber-orange', bg: 'rgba(255,120,0,0.1)' },
    { label: 'MEDIUM', value: data.threat_medium, color: 'text-cyber-yellow', border: 'border-cyber-yellow', bg: 'rgba(255,190,11,0.1)' },
    { label: 'LOW', value: data.threat_low, color: 'text-cyber-green', border: 'border-cyber-green', bg: 'rgba(0,255,136,0.1)' },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      {threats.map((t) => (
        <div
          key={t.label}
          className="cyber-card p-4 cyber-card-hover cursor-pointer"
          style={{ borderLeft: `3px solid ${t.border.replace('text-', 'var(--color-')}` }}
        >
          <div className={`text-2xl font-bold font-mono ${t.color}`} style={{ textShadow: `0 0 15px ${t.color.includes('red') ? 'rgba(255,23,68,0.5)' : t.color.includes('orange') ? 'rgba(255,120,0,0.5)' : t.color.includes('yellow') ? 'rgba(255,190,11,0.5)' : 'rgba(0,255,136,0.5)'}` }}>
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
    { name: 'Critical', value: data.threat_critical, color: '#ff1744' },
    { name: 'High', value: data.threat_high, color: '#ff7800' },
    { name: 'Medium', value: data.threat_medium, color: '#ffbe0b' },
    { name: 'Low', value: data.threat_low, color: '#00ff88' },
  ];

  return (
    <div className="cyber-card p-4">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <TrendingUp size={14} /> Severity Distribution
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 30 }}>
          <XAxis type="number" hide />
          <YAxis dataKey="name" type="category" width={60} tick={{ fill: '#64748b', fontSize: 11, fontFamily: 'monospace' }} />
          <Tooltip
            contentStyle={{ background: '#0d1117', border: '1px solid #1e293b', borderRadius: '8px', color: '#e2e8f0', fontFamily: 'monospace' }}
            itemStyle={{ fontFamily: 'monospace' }}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.color}40)` }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
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
                {alert.source_ip} → {alert.destination_ip}
              </div>
              <div className="text-xs text-cyber-textMuted mt-0.5">{alert.details}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default function OverviewTab() {
  const { timeRange, customTimeRange } = useStore();
  const [timelineData, setTimelineData] = useState<{ time: number; value: number }[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(true);
  const [sseTimelineData, setSSETimelineData] = useState<{ time: number; value: number }[]>([]);

  const { data: stats, isLoading: statsLoading, isError: statsError, error: statsErrorObj, refetch: refetchStats } = useQuery<StatsData>({
    queryKey: ['stats'],
    queryFn: api.stats,
  });
  const { data: alerts, isError: alertsError, error: alertsErrorObj, refetch: refetchAlerts } = useQuery<AlertsData>({
    queryKey: ['alerts'],
    queryFn: api.alerts,
  });

  // Show error state for the first query that fails
  if (statsError) return <QueryErrorState error={statsErrorObj} isError={statsError} onRetry={refetchStats} tabName="Overview" />;
  if (alertsError) return <QueryErrorState error={alertsErrorObj} isError={alertsError} onRetry={refetchAlerts} tabName="Overview" />;

  // Show loading state while stats are being fetched
  if (statsLoading || !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
      </div>
    );
  }

  // Fetch timeline data based on time range
  useEffect(() => {
    const fetchData = async () => {
      setTimelineLoading(true);
      setSSETimelineData([]); // Clear SSE data when time range changes
      try {
        let start: number;
        let end: number;

        if (timeRange === 'custom' && customTimeRange) {
          start = customTimeRange.start;
          end = customTimeRange.end;
        } else {
          const now = Math.floor(Date.now() / 1000);
          switch (timeRange) {
            case '1h': start = now - 3600; break;
            case '6h': start = now - 21600; break;
            case '24h': start = now - 86400; break;
            case '7d': start = now - 604800; break;
            case '30d': start = now - 2592000; break;
            default: start = now - 86400;
          }
          end = now;
        }

        const response = await fetch(`/api//timeline?start=${start}&end=${end}`);
        const result = await response.json();

        if (result.timeline) {
          const data = result.timeline.map((item: { time: string; count: number }) => ({
            time: Math.floor(new Date(item.time).getTime() / 1000),
            value: item.count,
          }));
          setTimelineData(data);
        }
      } catch (error) {
        console.error('Failed to fetch timeline data:', error);
      } finally {
        setTimelineLoading(false);
      }
    };

    fetchData();
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

  return (
    <TabQueryWrapper tab="overview" isLoading={statsLoading} isError={statsError} error={statsErrorObj} onRetry={refetchStats}>
      <div className="space-y-6">
        <ThreatSummary data={stats} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
        <StatBox value={(stats.events_24h || 0).toLocaleString()} label="Events (24h)" change={{ value: 12, positive: true }} />
        <StatBox value={(stats.blocked_24h || 0).toLocaleString()} label="Blocked" color="text-cyber-red" />
        <StatBox value={(stats.passed_24h || 0).toLocaleString()} label="Passed" color="text-cyber-green" />
        <StatBox value={stats.unique_ips} label="Unique IPs" />
        <StatBox value={stats.anomalies_detected} label="Anomalies" color="text-cyber-yellow" />
        <StatBox value={stats.alerts_sent} label="Alerts Sent" />
        <StatBox value={stats.rules_classified} label="Rules Classified" color="text-cyber-purple" />
        <StatBox value={stats.mutes_active} label="Active Mutes" />
      </div>

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
      </div>
    </TabQueryWrapper>
  );
}
