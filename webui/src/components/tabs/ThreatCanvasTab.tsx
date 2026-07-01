// ═══════════════════════════════════════════════════
// ThreatCanvasTab - P5-T1
// Unified threat canvas with active incidents,
// per-IP timeline, drill-down profiles, and recommended actions.
//
// ═══════════════════════════════════════════════════
// LAYOUT MOCKUP (ASCII)
// ═══════════════════════════════════════════════════
//
//  ┌─────────────────────────────────────────────────────────────────────┐
//  │ THREAT CANVAS                                          [auto-refresh]│
//  │ Unified threat intelligence with behavioral scoring                 │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │ SUMMARy STATS (row of cards)                                        │
//  │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
//  │ │ Active   │ │ Critical │ │   High   │ │  Unique  │ │Top Source│  │
//  │ │  12      │ │    3     │ │    5     │ │   18     │ │firewall  │  │
//  │ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │ ACTIVE INCIDENTS (ranked by behavior_score, scrollable list)         │
//  │ ┌─────────────────────────────────────────────────────────────────┐ │
//  │ │ [CRITICAL] 203.0.113.42    score:95   14 signals / 5 sources  │ │
//  │ │          ├─ firewall ── nginx ── ids ── dns ── zenarmor       │ │
//  │ │          └─ "Port scan detected on 42 ports, followed by...    │ │
//  │ ├─────────────────────────────────────────────────────────────────┤ │
//  │ │ [HIGH]      198.51.100.7   score:78    8 signals / 3 sources  │ │
//  │ │          ├─ firewall ── ids ── dns                            │ │
//  │ │          └─ "Repeated brute-force on SSH port 22..."           │ │
//  │ ├─────────────────────────────────────────────────────────────────┤ │
//  │ │ [MEDIUM]    192.0.2.15     score:45    3 signals / 2 sources  │ │
//  │ │          ├─ nginx ── dns                                    │ │
//  │ │          └─ "Suspicious path traversal attempts..."            │ │
//  │ └─────────────────────────────────────────────────────────────────┘ │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │ SELECTED IP TIMELINE (horizontal, click incident row to expand)     │
//  │ ┌─────────────────────────────────────────────────────────────────┐ │
//  │ │ 203.0.113.42  —  Timeline                                      │ │
//  │ │                                                                 │ │
//  │ │  00:00    04:00    08:00    12:00    16:00    20:00    24:00   │ │
//  │ │  ────●───────●─────●●●●─────●─────────●●●●●●●●●──●●●●●●──     │ │
//  │ │      fw        fw ids dns      nginx        ids   zenarmor     │ │
//  │ │      block     scan probe query      404     sig   policy     │ │
//  │ └─────────────────────────────────────────────────────────────────┘ │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │ IP DRILL-DOWN PANEL (right side, appears when IP selected)          │
//  │ ┌─────────────────────────────────────────────────────────────────┐ │
//  │ │ 203.0.113.42                              [resolve DNS] [geo]  │ │
//  │ │ ─────────────────────────────────────────────────────────────── │ │
//  │ │ Behavior Score: ████████████████████░░ 95/100                   │ │
//  │ │ Threat Level: CRITICAL   │   Classification: HOSTILE            │ │
//  │ │ First Seen: 2025-06-01   │   Last Seen: 2025-06-30 20:42        │ │
//  │ │ Total Events: 1,247      │   Blocked: 1,102   Passed: 145       │ │
//  │ │                                                                    │ │
//  │ │ Historical Score (Canvas 2D sparkline over 7 days)                │ │
//  │ │  ┌────────────────────────────────────────────────────────────┐   │ │
//  │ │  │  ╱╲    ╱╲╱╲  ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲    │   │ │
//  │ │  │ ──────────────────────────────────────────────────────────│   │ │
//  │ │  └────────────────────────────────────────────────────────────┘   │ │
//  │ │                                                                    │ │
//  │ │ Signal Breakdown:                                                  │ │
//  │ │   firewall ████████████████████░░░░  45%                          │ │
//  │ │   ids      ██████████████░░░░░░░░░░  28%                          │ │
//  │ │   dns      ████████░░░░░░░░░░░░░░░░  14%                          │ │
//  │ │   nginx    ████░░░░░░░░░░░░░░░░░░░░   8%                          │ │
//  │ │   zenarmor ███░░░░░░░░░░░░░░░░░░░░░   5%                          │ │
//  │ └─────────────────────────────────────────────────────────────────┘ │
//  ├─────────────────────────────────────────────────────────────────────┤
//  │ RECOMMENDED ACTIONS (bottom panel)                                  │
//  │ ┌─────────────────────────────────────────────────────────────────┐ │
//  │ │ [IMMEDIATE] BLOCK 203.0.113.42                                 │ │
//  │ │          Score 95, 5-source attack chain spanning 24h           │ │
//  │ │          Command: firewall block rule for 203.0.113.42          │ │
//  │ │          [Execute]  [Dismiss]                                    │ │
//  │ ├─────────────────────────────────────────────────────────────────┤ │
//  │ │ [HIGH]      WATCHLIST 198.51.100.7                             │ │
//  │ │          Score 78, repeated SSH brute-force from known bad ASN  │ │
//  │ │          [Execute]  [Dismiss]                                    │ │
//  │ ├─────────────────────────────────────────────────────────────────┤ │
//  │ │ [MEDIUM]    INVESTIGATE 192.0.2.15                             │ │
//  │ │          Score 45, path traversal attempts — may be misconfig   │ │
//  │ │          [Execute]  [Dismiss]                                    │ │
//  │ └─────────────────────────────────────────────────────────────────┘ │
//  └─────────────────────────────────────────────────────────────────────┘
//
// ═══════════════════════════════════════════════════
// DATA MODEL
// ═══════════════════════════════════════════════════
//
// /api/threat-canvas returns:
// {
//   "incidents": [
//     {
//       "incident_id": "inc_abc123",
//       "ip": "203.0.113.42",
//       "src_hostname": "evil.example.com",
//       "dst_hostname": "webserver.internal",
//       "threat_level": "critical",
//       "behavior_score": 95,
//       "signal_count": 14,
//       "source_count": 5,
//       "sources": ["firewall", "nginx", "ids", "dns", "zenarmor"],
//       "signal_types": ["PORT_SCAN", "BRUTE_FORCE", "SIGNATURE_HIT"],
//       "phases": ["recon", "probe", "attack", "exploit"],
//       "first_seen": "2025-06-01T00:00:00Z",
//       "last_seen": "2025-06-30T20:42:00Z",
//       "narrative": "Port scan detected on 42 ports...",
//       "timeline": [
//         {"timestamp": "...", "source": "firewall", "signal_type": "PORT_SCAN", "severity": "HIGH", "description": "..."}
//       ],
//       "is_active": true
//     }
//   ],
//   "actions": [
//     {
//       "incident_id": "inc_abc123",
//       "ip": "203.0.113.42",
//       "action": "block_ip",
//       "priority": "immediate",
//       "reason": "Score 95, 5-source attack chain",
//       "command": "firewall block rule for 203.0.113.42"
//     }
//   ],
//   "summary": {
//     "total_active": 12,
//     "total_incidents": 30,
//     "critical_count": 3,
//     "high_count": 5,
//     "medium_count": 8,
//     "low_count": 14,
//     "unique_ips": 18,
//     "unique_sources": 5,
//     "top_source": "firewall",
//     "top_source_count": 142
//   }
// }
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { ThreatCanvasData, ThreatCanvasIncident, RecommendedAction, TimelineEvent } from '@/types';
import { CYBER, severityStyle } from '@/utils/colors';
import { IncidentTimelineSkeleton } from '@/components/SkeletonLoaders';
import { TabQueryError } from '@/components/TabShell';
import {
  ShieldAlert, AlertTriangle, Ban, Eye, Search, Clock,
  ChevronDown, ChevronUp, X, Activity, Network, Terminal,
  Shield, ShieldCheck, Zap, ArrowRight,
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

// ── Horizontal Timeline (Canvas-free, DOM-based) ──
function HorizontalTimeline({ events }: { events: TimelineEvent[] }) {
  if (!events || events.length === 0) return null;

  const sorted = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const minTime = new Date(sorted[0].timestamp).getTime();
  const maxTime = new Date(sorted[sorted.length - 1].timestamp).getTime();
  const range = Math.max(maxTime - minTime, 1);

  return (
    <div className="relative mt-4">
      {/* Time axis */}
      <div className="flex justify-between text-xs text-cyber-textMuted font-mono mb-2">
        <span>{new Date(sorted[0].timestamp).toLocaleTimeString()}</span>
        <span>{new Date(sorted[sorted.length - 1].timestamp).toLocaleTimeString()}</span>
      </div>
      {/* Timeline bar */}
      <div className="relative h-8 bg-cyber-darker rounded border border-cyber-border overflow-hidden">
        {sorted.map((evt, i) => {
          const pct = ((new Date(evt.timestamp).getTime() - minTime) / range) * 100;
          const color = SOURCE_COLORS[evt.source] || CYBER.textMuted;
          return (
            <div
              key={i}
              className="absolute top-0 bottom-0 flex items-center"
              style={{ left: `${pct}%`, transform: 'translateX(-50%)' }}
            >
              <div
                className="w-3 h-3 rounded-full border-2 flex-shrink-0"
                style={{ backgroundColor: color, borderColor: `${color}60`, boxShadow: `0 0 4px ${color}` }}
                title={`${evt.source}: ${evt.signal_type} (${evt.description})`}
              />
            </div>
          );
        })}
      </div>
      {/* Source labels */}
      <div className="flex flex-wrap gap-1 mt-2">
        {[...new Set(sorted.map(e => e.source))].map(src => (
          <SourceBadge key={src} source={src} />
        ))}
      </div>
    </div>
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
  const style = severityStyle(incident.threat_level);
  const threatColor =
    incident.threat_level === 'critical' ? CYBER.red :
    incident.threat_level === 'high' ? CYBER.orange :
    incident.threat_level === 'medium' ? CYBER.yellow :
    CYBER.green;

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
          style={{ backgroundColor: threatColor, boxShadow: `0 0 6px ${threatColor}` }}
        />
      </div>

      {/* Severity badge */}
      <span
        className="px-2 py-0.5 text-xs rounded font-bold uppercase flex-shrink-0"
        style={{ color: threatColor, backgroundColor: `${threatColor}15`, border: `1px solid ${threatColor}30` }}
      >
        {incident.threat_level}
      </span>

      {/* IP + hostname */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-bold text-cyber-text">{incident.ip}</span>
          {incident.src_hostname && (
            <span className="text-xs text-cyber-accent/80 font-mono truncate">({incident.src_hostname})</span>
          )}
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
      </div>

      {/* Right column: stats */}
      <div className="flex-shrink-0 text-right">
        <div className="text-xs text-cyber-textMuted font-mono">
          score: <span style={{ color: threatColor, fontWeight: 'bold' }}>{incident.behavior_score}</span>
        </div>
        <div className="text-xs text-cyber-textMuted font-mono">{incident.signal_count} signals</div>
        <div className="text-xs text-cyber-textMuted font-mono">{incident.source_count} sources</div>
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

// ── IP Drill-down Panel ──
function IpDrillDown({ incident }: { incident: ThreatCanvasIncident }) {
  const threatColor =
    incident.threat_level === 'critical' ? CYBER.red :
    incident.threat_level === 'high' ? CYBER.orange :
    incident.threat_level === 'medium' ? CYBER.yellow :
    CYBER.green;

  return (
    <div className="bg-cyber-panel border rounded-lg p-4 space-y-4" style={{ borderColor: `${threatColor}30` }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: threatColor, boxShadow: `0 0 8px ${threatColor}` }} />
          <h3 className="font-mono text-lg font-bold text-cyber-text">{incident.ip}</h3>
          {incident.src_hostname && (
            <span className="text-sm text-cyber-accent font-mono">({incident.src_hostname})</span>
          )}
          {incident.dst_hostname && (
            <span className="text-xs text-cyber-textMuted">→ {incident.dst_hostname}</span>
          )}
        </div>
        <div className="flex gap-2">
          <button className="px-2 py-1 text-xs font-mono text-cyber-accent border border-cyber-accent/30 rounded hover:bg-cyber-accent/10">
            Resolve DNS
          </button>
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
            <span className="text-xs font-bold font-mono uppercase" style={{ color: threatColor }}>{incident.threat_level}</span>
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

      {/* Signal type tags */}
      {incident.signal_types.length > 0 && (
        <div>
          <h4 className="text-xs text-cyber-textMuted uppercase tracking-wider mb-2">Signal Types</h4>
          <div className="flex flex-wrap gap-1">
            {incident.signal_types.map(s => (
              <span key={s} className="px-2 py-0.5 text-xs rounded bg-cyber-accent/10 text-cyber-accent font-mono border border-cyber-accent/20">
                {s}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Horizontal Timeline */}
      {incident.timeline && incident.timeline.length > 0 && (
        <div>
          <h4 className="text-xs text-cyber-textMuted uppercase tracking-wider mb-2">Timeline</h4>
          <HorizontalTimeline events={incident.timeline} />
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
    <div
      className="flex items-start gap-3 p-3 border-b border-cyber-border/30"
    >
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
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showActiveOnly, setShowActiveOnly] = useState(true);
  const [filterThreat, setFilterThreat] = useState<string>('all');

  const { data, isLoading, isError, error, refetch } = useQuery<ThreatCanvasData>({
    queryKey: ['threat-canvas'],
    queryFn: api.threatCanvas,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  // Selected incident for drill-down
  const selectedIncident = useMemo(() => {
    if (!selectedId || !data) return null;
    return data.incidents.find(i => i.incident_id === selectedId) || null;
  }, [selectedId, data]);

  // Filtered incidents
  const filtered = useMemo(() => {
    if (!data) return [];
    let result = data.incidents;
    if (showActiveOnly) result = result.filter(i => i.is_active);
    if (filterThreat !== 'all') result = result.filter(i => i.threat_level === filterThreat);
    return result.sort((a, b) => b.behavior_score - a.behavior_score);
  }, [data, showActiveOnly, filterThreat]);

  // Filtered actions
  const filteredActions = useMemo(() => {
    if (!data) return [];
    return data.actions.sort((a, b) => {
      const order = { immediate: 0, high: 1, medium: 2, low: 3 };
      return (order[a.priority] ?? 99) - (order[b.priority] ?? 99);
    });
  }, [data]);

  if (isLoading) return <IncidentTimelineSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Threat Canvas" />;

  const summary = data?.summary;
  const noData = !data || data.incidents.length === 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gradient-cyber">Threat Canvas</h2>
          <p className="text-xs text-cyber-textMuted mt-1">Unified threat intelligence with behavioral scoring and cross-source correlation</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={refetch} className="p-2 rounded-md text-cyber-textMuted hover:text-cyber-accent hover:bg-cyber-panel/50 transition-colors cursor-pointer">
            <Activity size={16} />
          </button>
        </div>
      </div>

      {/* Empty state */}
      {noData && (
        <div className="p-12 text-center text-cyber-textMuted text-sm">
          <ShieldCheck size={48} className="mx-auto mb-4 opacity-50" />
          <p className="mb-2">No threat data available yet.</p>
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
            onClick={() => setShowActiveOnly(!showActiveOnly)}
            className={`px-3 py-1.5 rounded text-xs font-semibold border transition-all cursor-pointer ${
              showActiveOnly ? 'border-cyber-accent text-cyber-accent bg-cyber-accent/10' : 'border-cyber-border/30 text-cyber-textMuted'
            }`}
          >
            Active Only
          </button>
          {['all', 'critical', 'high', 'medium', 'low'].map(s => {
            const active = filterThreat === s;
            const color = s === 'all' ? CYBER.accent : severityStyle(s).color;
            return (
              <button key={s} onClick={() => setFilterThreat(s)}
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

      {/* Main content: two-column layout */}
      {summary && !noData && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Incident list */}
          <div className="bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden">
            <div className="p-3 border-b border-cyber-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-cyber-text flex items-center gap-2">
                <ShieldAlert size={14} style={{ color: CYBER.red }} />
                Active Incidents
              </h3>
              <span className="text-xs text-cyber-textMuted font-mono">{filtered.length} shown</span>
            </div>
            <div>
              {filtered.map(inc => (
                <IncidentRow
                  key={inc.incident_id}
                  incident={inc}
                  isSelected={selectedId === inc.incident_id}
                  onClick={() => setSelectedId(selectedId === inc.incident_id ? null : inc.incident_id)}
                />
              ))}
            </div>
          </div>

          {/* Right: Drill-down panel or empty state */}
          <div>
            {selectedIncident ? (
              <IpDrillDown incident={selectedIncident} />
            ) : (
              <div className="bg-cyber-panel border border-cyber-border rounded-lg p-12 text-center text-cyber-textMuted">
                <Network size={48} className="mx-auto mb-4 opacity-50" />
                <p className="text-sm">Select an incident to view its behavioral profile and timeline</p>
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
