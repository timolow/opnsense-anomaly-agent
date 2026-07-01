// ═══════════════════════════════════════════════════
// ThreatCanvasTab - P5-T2
// Unified threat canvas with 3-panel layout:
//   Left: Active incidents (scrollable list)
//   Center: IP timeline (Canvas 2D)
//   Right: Detail + recommended actions
//
// Wires to Zustand store for state management.
// Uses ThreatCanvasSkeleton loader.
// Uses Canvas 2D for timeline chart.
// ═══════════════════════════════════════════════════

import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { format_ip } from '@/utils/formatIp';
import { useQuery } from '@tanstack/react-query';
import { useStore } from '@/store';
import { api } from '@/api';
import type { ThreatCanvasData, ThreatCanvasIncident, RecommendedAction, TimelineEvent, IpTimelineData, IpTimelineEvent } from '@/types';
import { CYBER, severityStyle } from '@/utils/colors';
import { ThreatCanvasSkeleton } from '@/components/SkeletonLoaders';
import { TabQueryError } from '@/components/TabShell';
import CanvasBarChart from '@/components/charts/CanvasBarChart';
import ThreatTimeline from '@/components/charts/ThreatTimeline';
import { useThreatCanvasSSE } from '@/hooks/useThreatCanvasSSE';
import {
  ShieldAlert, Ban, Eye, Search, AlertTriangle,
  ChevronDown, ChevronUp, Activity, Network, ShieldCheck, Zap, ArrowRight,
} from 'lucide-react';

// ── Source badge colors ──
const SOURCE_COLORS: Record<string, string> = {
  firewall: CYBER.red,
  nginx: CYBER.orange,
  ids: '#ff00ff',
  dns: CYBER.accent,
  zenarmor: CYBER.purple,
  wan_flap: CYBER.yellow,
  service: CYBER.green,
  baseline: '#8338ec',
};

// ── Priority colors ──
const PRIORITY_COLORS: Record<string, string> = {
  immediate: CYBER.red,
  high: CYBER.orange,
  medium: CYBER.yellow,
  low: CYBER.green,
};

// ── Threat level color ──
function threatColor(level: string): string {
  return level === 'critical' ? CYBER.red
    : level === 'high' ? CYBER.orange
    : level === 'medium' ? CYBER.yellow
    : CYBER.green;
}

// ── Time active helper ──
function timeActive(lastSeen: string | undefined): string {
  if (!lastSeen) return 'N/A';
  const diff = Date.now() - new Date(lastSeen).getTime();
  const abs = Math.abs(diff);
  const prefix = diff < 0 ? 'in ' : '';
  if (abs < 60_000) return `${prefix}${Math.round(abs / 1000)}s ago`;
  if (abs < 3_600_000) return `${prefix}${Math.round(abs / 60_000)}m ago`;
  if (abs < 86_400_000) return `${prefix}${Math.round(abs / 3_600_000)}h ago`;
  return `${prefix}${Math.round(abs / 86_400_000)}d ago`;
}

// ── Source Badge ──
function SourceBadge({ source }: { source: string }) {
  const color = SOURCE_COLORS[source] || CYBER.textMuted;
  return (
    <span
      className="px-2 py-0.5 text-xs rounded font-mono border"
      style={{ color, backgroundColor: `${color}15`, borderColor: `${color}40` }}
    >
      {source}
    </span>
  );
}

// ── Phase indicator ──
function PhaseBadge({ phase, active }: { phase: string; active: boolean }) {
  const phaseColors: Record<string, string> = {
    recon: CYBER.accent,
    probe: CYBER.orange,
    attack: CYBER.red,
    exploit: '#ff00ff',
  };
  const color = phaseColors[phase] || CYBER.textMuted;
  return (
    <span
      className={`px-1.5 py-0.5 text-xs rounded font-semibold font-mono border transition-all ${
        active ? '' : 'opacity-40 border-cyber-border/20 text-cyber-textMuted'
      }`}
      style={active ? { color, borderColor: `${color}60`, backgroundColor: `${color}15` } : {}}
    >
      {phase.toUpperCase()}
    </span>
  );
}

// ── Behavior Score Bar ──
function ScoreBar({ score }: { score: number }) {
  const color = score >= 90 ? CYBER.red : score >= 70 ? CYBER.orange : score >= 40 ? CYBER.yellow : CYBER.green;
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-3 bg-cyber-darker rounded overflow-hidden border border-cyber-border">
        <div
          className="h-full rounded transition-all duration-500"
          style={{ width: `${score}%`, backgroundColor: color, boxShadow: `0 0 8px ${color}60` }}
        />
      </div>
      <span className="text-sm font-mono font-bold" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

// ── Incident Row ──
function IncidentRow({ incident, isSelected, onClick }: { incident: ThreatCanvasIncident; isSelected: boolean; onClick: () => void }) {
  const color = threatColor(incident.threat_level);

  return (
    <div
      className={`flex items-start gap-3 p-3 border-b border-cyber-border/30 cursor-pointer transition-all ${
        isSelected ? 'bg-cyber-accent/5' : 'hover:bg-cyber-panel/50'
      }`}
      onClick={onClick}
    >
      {/* Threat level dot */}
      <div className="flex-shrink-0 mt-1">
        <div
          className="w-2.5 h-2.5 rounded-full"
          style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
        />
      </div>

      {/* Severity badge */}
      <span
        className="px-2 py-0.5 text-xs rounded font-bold uppercase flex-shrink-0"
        style={{ color, backgroundColor: `${color}15`, border: `1px solid ${color}30` }}
      >
        {incident.threat_level}
      </span>

      {/* IP + hostname */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-bold text-cyber-text">{format_ip(incident.ip, incident.src_hostname)}</span>
        </div>
        <div className="flex flex-wrap gap-1 mt-1">
          {incident.sources.map(src => (
            <SourceBadge key={src} source={src} />
          ))}
        </div>
        {/* Attack chain phases */}
        {incident.phases && incident.phases.length > 0 && (
          <div className="flex items-center gap-1 mt-1">
            {['recon', 'probe', 'attack', 'exploit'].map((phase, i) => (
              <div key={phase} className="flex items-center gap-1">
                <PhaseBadge phase={phase} active={incident.phases.includes(phase)} />
                {i < 3 && <ArrowRight size={10} className="text-cyber-textMuted" />}
              </div>
            ))}
          </div>
        )}
        {/* Narrative preview */}
        {incident.narrative && (
          <p className="text-xs text-cyber-textMuted mt-1 truncate">{incident.narrative}</p>
        )}
        {/* Explanation preview */}
        {incident.explanation && (
          <p className="text-xs text-cyber-accent/70 mt-0.5 truncate">{incident.explanation}</p>
        )}
      </div>

      {/* Right column: stats */}
      <div className="flex-shrink-0 text-right">
        <div className="text-xs text-cyber-textMuted font-mono">
          score: <span style={{ color, fontWeight: 'bold' }}>{incident.behavior_score}</span>
        </div>
        <div className="text-xs text-cyber-textMuted font-mono">{incident.signal_count} signals</div>
        <div className="text-xs text-cyber-textMuted font-mono">{incident.source_count} sources</div>
        <div className="text-xs font-mono" style={{ color: CYBER.accent }}>
          {timeActive(incident.last_seen)}
        </div>
        {!incident.is_active && (
          <span className="text-xs text-cyber-green/60">resolved</span>
        )}
      </div>

      {/* Expand arrow */}
      <div className="flex-shrink-0 text-cyber-textMuted">
        {isSelected ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </div>
    </div>
  );
}

// ── IP Drill-down Panel (Right side) ──
function IpDrillDown({ incident }: { incident: ThreatCanvasIncident }) {
  const color = threatColor(incident.threat_level);

  // Signal breakdown data for Canvas bar chart
  const signalBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    incident.sources.forEach(s => { counts[s] = 0; });
    incident.timeline?.forEach(evt => {
      if (counts[evt.source] !== undefined) counts[evt.source]++;
    });
    // Fallback: distribute signal_count across sources
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) {
      const per = Math.floor(incident.signal_count / incident.sources.length);
      incident.sources.forEach(s => { counts[s] = per; });
    }
    return incident.sources.map(src => ({
      name: src,
      value: counts[src],
      color: SOURCE_COLORS[src] || CYBER.textMuted,
    }));
  }, [incident]);

  return (
    <div className="bg-cyber-panel border rounded-lg p-4 space-y-4" style={{ borderColor: `${color}30` }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }} />
          <h3 className="font-mono text-lg font-bold text-cyber-text">{format_ip(incident.ip, incident.src_hostname)}</h3>
          {incident.dst_hostname && (
            <span className="text-xs text-cyber-textMuted">→ {incident.dst_hostname}</span>
          )}
        </div>
      </div>

      {/* Score + Level */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <span className="text-xs text-cyber-textMuted uppercase">Behavior Score</span>
          <ScoreBar score={incident.behavior_score} />
        </div>
        <div className="space-y-2">
          <div className="flex justify-between">
            <span className="text-xs text-cyber-textMuted">Threat Level</span>
            <span className="text-xs font-bold font-mono uppercase" style={{ color }}>{incident.threat_level}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-cyber-textMuted">First Seen</span>
            <span className="text-xs font-mono text-cyber-text">
              {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'N/A'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-cyber-textMuted">Last Seen</span>
            <span className="text-xs font-mono text-cyber-text">
              {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-xs text-cyber-textMuted">Time Active</span>
            <span className="text-xs font-mono font-bold" style={{ color: CYBER.accent }}>
              {timeActive(incident.last_seen)}
            </span>
          </div>
        </div>
      </div>

      {/* Signal count stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Signals', value: incident.signal_count, color: CYBER.accent },
          { label: 'Sources', value: incident.source_count, color: CYBER.purple },
          { label: 'Types', value: incident.signal_types.length, color: CYBER.orange },
          { label: 'Phases', value: incident.phases.length, color: '#ff00ff' },
        ].map(s => (
          <div key={s.label} className="bg-cyber-darker rounded p-2 text-center">
            <span className="text-xs text-cyber-textMuted uppercase">{s.label}</span>
            <div className="text-lg font-mono font-bold" style={{ color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Narrative */}
      {incident.narrative && (
        <div className="rounded-lg border border-cyber-accent/20 bg-cyber-accent/5 p-3">
          <h4 className="text-xs text-cyber-accent uppercase tracking-wider mb-1 font-semibold">Narrative</h4>
          <p className="text-sm text-cyber-text/90 leading-relaxed">{incident.narrative}</p>
        </div>
      )}

      {/* Explanation */}
      {incident.explanation && (
        <div className="rounded-lg border border-cyber-purple/20 bg-cyber-purple/5 p-3">
          <h4 className="text-xs text-cyber-purple uppercase tracking-wider mb-1 font-semibold">Why Flagged</h4>
          <p className="text-sm text-cyber-text/90 leading-relaxed">{incident.explanation}</p>
        </div>
      )}

      {/* Signal breakdown bar chart (Canvas 2D) */}
      {signalBreakdown.length > 0 && (
        <div>
          <h4 className="text-xs text-cyber-textMuted uppercase tracking-wider mb-2">Signal Breakdown</h4>
          <CanvasBarChart data={signalBreakdown} height={120} barSize={80} />
        </div>
      )}
    </div>
  );
}

// ── Recommended Action Row ──
function ActionRow({ action }: { action: RecommendedAction }) {
  const priorityColor = PRIORITY_COLORS[action.priority] || CYBER.textMuted;

  const actionIcons: Record<string, any> = {
    block_ip: <Ban size={14} />,
    add_watchlist: <Eye size={14} />,
    investigate: <Search size={14} />,
    escalate: <AlertTriangle size={14} />,
    suppress: <ShieldCheck size={14} />,
  };

  return (
    <div className="flex items-start gap-3 p-3 border-b border-cyber-border/30">
      {/* Priority badge */}
      <span
        className="px-2 py-0.5 text-xs rounded font-bold uppercase flex-shrink-0"
        style={{ color: priorityColor, backgroundColor: `${priorityColor}15`, border: `1px solid ${priorityColor}30` }}
      >
        {action.priority}
      </span>

      {/* Action icon + type */}
      <div className="flex items-center gap-2 flex-1">
        <span style={{ color: priorityColor }}>{actionIcons[action.action]}</span>
        <div>
          <div className="text-sm font-bold text-cyber-text">
            {action.action.replace('_', ' ')} <span className="font-mono">{action.ip}</span>
          </div>
          <p className="text-xs text-cyber-textMuted mt-0.5">{action.reason}</p>
          {action.command && (
            <code className="text-xs font-mono text-cyber-accent/70 mt-1 block">{action.command}</code>
          )}
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 flex-shrink-0">
        <button
          className="px-3 py-1 text-xs font-semibold rounded border transition-all cursor-pointer"
          style={{ color: priorityColor, borderColor: `${priorityColor}40`, backgroundColor: `${priorityColor}10` }}
        >
          Execute
        </button>
        <button className="px-2 py-1 text-xs text-cyber-textMuted border border-cyber-border/30 rounded hover:bg-cyber-panel/50 cursor-pointer">
          Dismiss
        </button>
      </div>
    </div>
  );
}

// ── Main Tab Component ──
export default function ThreatCanvasTab() {
  // Zustand store for selection + filters
  const {
    threatCanvasSelectedId,
    setThreatCanvasSelectedId,
    threatCanvasFilterActive,
    setThreatCanvasFilterActive,
    threatCanvasFilterThreat,
    setThreatCanvasFilterThreat,
    timeRange,
  } = useStore();

  const { data, isLoading, isError, error, refetch } = useQuery<ThreatCanvasData>({
    queryKey: ['threat-canvas'],
    queryFn: api.threatCanvas,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  // SSE: refetch when live events arrive + track connection state
  const handleSSEEvent = useCallback(() => {
    refetch();
  }, [refetch]);
  const { isConnected } = useThreatCanvasSSE(handleSSEEvent);

  // Selected incident for center panel (timeline) + right panel (drill-down)
  const selectedIncident = useMemo(() => {
    if (!threatCanvasSelectedId || !data) return null;
    return data.incidents.find(i => i.incident_id === threatCanvasSelectedId) || null;
  }, [threatCanvasSelectedId, data]);

  // Fetch full timeline data from /api/ip-timeline using global time range
  const { data: timelineData } = useQuery<IpTimelineData>({
    queryKey: ['ip-timeline', selectedIncident?.ip, timeRange],
    queryFn: () => api.ipTimeline(selectedIncident!.ip, timeRange),
    enabled: !!selectedIncident,
    staleTime: 10_000,
  });

  // Merge timeline events: prefer /api/ip-timeline events, fall back to incident.timeline
  const timelineEvents: (TimelineEvent | IpTimelineEvent)[] = useMemo(() => {
    if (timelineData?.events?.length) {
      return timelineData.events;
    }
    return selectedIncident?.timeline ?? [];
  }, [timelineData, selectedIncident]);

  // Filtered incidents
  const filtered = useMemo(() => {
    if (!data) return [];
    let result = data.incidents;
    if (threatCanvasFilterActive) result = result.filter(i => i.is_active);
    if (threatCanvasFilterThreat !== 'all') result = result.filter(i => i.threat_level === threatCanvasFilterThreat);
    return result.sort((a, b) => b.behavior_score - a.behavior_score);
  }, [data, threatCanvasFilterActive, threatCanvasFilterThreat]);

  // Filtered actions
  const filteredActions = useMemo(() => {
    if (!data) return [];
    return data.actions.sort((a, b) => {
      const order = { immediate: 0, high: 1, medium: 2, low: 3 };
      return (order[a.priority] ?? 99) - (order[b.priority] ?? 99);
    });
  }, [data]);

  if (isLoading) return <ThreatCanvasSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Threat Canvas" />;

  const summary = data?.summary;
  const noData = !data || data.incidents.length === 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-gradient-cyber">Threat Canvas</h2>
            {/* Live indicator — pulsing dot when SSE connected */}
            <span
              className={`inline-block w-2 h-2 rounded-full transition-colors duration-300 ${
                isConnected ? 'bg-cyber-green' : 'bg-cyber-textMuted'
              }`}
              style={isConnected ? { boxShadow: '0 0 6px #00ff41', animation: 'pulse 2s infinite' } : {}}
              title={isConnected ? 'Live SSE connected' : 'SSE disconnected'}
            />
          </div>
          <p className="text-xs text-cyber-textMuted mt-1">Unified threat intelligence with behavioral scoring and cross-source correlation</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="p-2 rounded-md text-cyber-textMuted hover:text-cyber-accent hover:bg-cyber-panel/50 transition-colors cursor-pointer">
            <Activity size={16} />
          </button>
        </div>
      </div>

      {/* Empty state */}
      {noData && (
        <div className="p-12 text-center text-cyber-textMuted text-sm">
          <ShieldCheck size={48} className="mx-auto mb-4 opacity-50" style={{ color: CYBER.green }} />
          <p className="mb-2 text-cyber-green font-semibold">No active incidents — all clear</p>
          <p className="text-xs">The Threat Canvas will populate as incidents are correlated across firewall, nginx, IDS, DNS, and ZenArmor sources.</p>
        </div>
      )}

      {/* Summary Stats */}
      {summary && !noData && (
        <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
          {[
            { label: 'Active', value: summary.total_active, color: CYBER.red },
            { label: 'Critical', value: summary.critical_count, color: CYBER.red },
            { label: 'High', value: summary.high_count, color: CYBER.orange },
            { label: 'Medium', value: summary.medium_count, color: CYBER.yellow },
            { label: 'Unique IPs', value: summary.unique_ips, color: CYBER.accent },
            { label: 'Top Source', value: summary.top_source, color: SOURCE_COLORS[summary.top_source] || CYBER.textMuted, isText: true },
          ].map(c => (
            <div key={c.label} className="bg-cyber-panel border border-cyber-border rounded-lg p-3">
              <span className="text-xs text-cyber-textMuted uppercase">{c.label}</span>
              <div className="text-xl font-bold font-mono" style={{ color: c.color }}>
                {c.isText ? c.value : c.value}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filter bar */}
      {summary && !noData && (
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setThreatCanvasFilterActive(!threatCanvasFilterActive)}
            className={`px-3 py-1.5 rounded text-xs font-semibold border transition-all cursor-pointer ${
              threatCanvasFilterActive ? 'border-cyber-accent text-cyber-accent bg-cyber-accent/10' : 'border-cyber-border/30 text-cyber-textMuted'
            }`}
          >
            Active Only
          </button>
          {['all', 'critical', 'high', 'medium', 'low'].map(s => {
            const active = threatCanvasFilterThreat === s;
            const color = s === 'all' ? CYBER.accent : severityStyle(s).color;
            return (
              <button key={s} onClick={() => setThreatCanvasFilterThreat(s)}
                className={`px-3 py-1.5 rounded text-xs font-semibold uppercase border transition-all cursor-pointer ${
                  active ? 'border-opacity-100' : 'border-cyber-border/30 text-cyber-textMuted'
                }`}
                style={active ? { borderColor: color, color, backgroundColor: `${color}15` } : {}}
              >
                {s}
              </button>
            );
          })}
        </div>
      )}

      {/* ═══ 3-Panel Layout: Incidents | Timeline | Detail ═══ */}
      {summary && !noData && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* ── Left Panel: Active Incidents ── */}
          <div className="bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden">
            <div className="p-3 border-b border-cyber-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-cyber-text flex items-center gap-2">
                <ShieldAlert size={14} style={{ color: CYBER.red }} />
                Active Incidents
              </h3>
              <span className="text-xs text-cyber-textMuted font-mono">{filtered.length} shown</span>
            </div>
            <div className="max-h-[500px] overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="p-8 text-center text-cyber-textMuted text-sm">
                  <ShieldCheck size={32} className="mx-auto mb-3 opacity-50" style={{ color: CYBER.green }} />
                  <p className="text-cyber-green font-semibold">No active incidents — all clear</p>
                  <p className="text-xs mt-1">
                    {threatCanvasFilterActive || threatCanvasFilterThreat !== 'all'
                      ? 'No incidents match the active filters.'
                      : 'Waiting for correlated threat data...'}
                  </p>
                </div>
              ) : (
                filtered.map(inc => (
                  <IncidentRow
                    key={inc.incident_id}
                    incident={inc}
                    isSelected={threatCanvasSelectedId === inc.incident_id}
                    onClick={() => setThreatCanvasSelectedId(
                      threatCanvasSelectedId === inc.incident_id ? null : inc.incident_id
                    )}
                  />
                ))
              )}
            </div>
          </div>

          {/* ── Center Panel: IP Timeline (Canvas 2D) ── */}
          <div className="bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden">
            <div className="p-3 border-b border-cyber-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-cyber-text flex items-center gap-2">
                <Network size={14} style={{ color: CYBER.accent }} />
                IP Timeline
              </h3>
              {selectedIncident && (
                <span className="text-xs text-cyber-textMuted font-mono">{timelineEvents.length} events</span>
              )}
            </div>
            <div className="p-3">
              {selectedIncident ? (
                <ThreatTimeline
                  events={timelineEvents}
                  ip={selectedIncident.ip}
                  height={420}
                />
              ) : (
                <div className="flex items-center justify-center h-[420px] text-cyber-textMuted text-sm text-center">
                  <div>
                    <Network size={32} className="mx-auto mb-3 opacity-50" />
                    <p>Select an incident to view its timeline</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ── Right Panel: Detail + Actions ── */}
          <div>
            {selectedIncident ? (
              <IpDrillDown incident={selectedIncident} />
            ) : (
              <div className="bg-cyber-panel border border-cyber-border rounded-lg p-12 text-center text-cyber-textMuted">
                <ShieldAlert size={48} className="mx-auto mb-4 opacity-50" />
                <p className="text-sm">Select an incident to view its behavioral profile</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Recommended Actions Panel */}
      {filteredActions.length > 0 && (
        <div className="bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden">
          <div className="p-3 border-b border-cyber-border flex items-center gap-2">
            <Zap size={14} style={{ color: CYBER.orange }} />
            <h3 className="text-sm font-semibold text-cyber-text">Recommended Actions</h3>
            <span className="text-xs text-cyber-textMuted font-mono ml-auto">{filteredActions.length} pending</span>
          </div>
          {filteredActions.map((action, i) => (
            <ActionRow key={`${action.incident_id}-${i}`} action={action} />
          ))}
        </div>
      )}
    </div>
  );
}
