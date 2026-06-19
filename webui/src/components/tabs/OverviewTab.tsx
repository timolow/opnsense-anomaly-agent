// ═══════════════════════════════════════════════════
// Overview Tab - Main dashboard with stats, threats, timeline
// ═══════════════════════════════════════════════════

import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { StatsData, AlertsData } from '@/types';
import {
  AlertTriangle, Shield, Ban, Eye, TrendingUp,
  Activity, Clock, ArrowUpRight, ArrowDownRight,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

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
    <div className="grid grid-cols-4 gap-3 mb-6">
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
  const { data: stats } = useQuery<StatsData>({
    queryKey: ['stats'],
    queryFn: api.stats,
  });
  const { data: alerts } = useQuery<AlertsData>({
    queryKey: ['alerts'],
    queryFn: api.alerts,
  });

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <ThreatSummary data={stats} />

      <div className="grid grid-cols-4 gap-4">
        <StatBox value={stats.events_24h.toLocaleString()} label="Events (24h)" change={{ value: 12, positive: true }} />
        <StatBox value={stats.blocked_24h.toLocaleString()} label="Blocked" color="text-cyber-red" />
        <StatBox value={stats.passed_24h.toLocaleString()} label="Passed" color="text-cyber-green" />
        <StatBox value={stats.unique_ips} label="Unique IPs" />
        <StatBox value={stats.anomalies_detected} label="Anomalies" color="text-cyber-yellow" />
        <StatBox value={stats.alerts_sent} label="Alerts Sent" />
        <StatBox value={stats.rules_classified} label="Rules Classified" color="text-cyber-purple" />
        <StatBox value={stats.mutes_active} label="Active Mutes" />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2">
          <SeverityChart data={stats} />
        </div>
        <ActivityFeed alerts={alerts || { anomalies: [] }} />
      </div>
    </div>
  );
}
