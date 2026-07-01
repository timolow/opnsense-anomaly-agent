// ═══════════════════════════════════════════════════
// IncidentTimelineTab - ML-PIVOT-10
// Correlated security incidents with attack chain
// visualization, detail view, and severity sorting.
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CYBER, severityStyle } from '@/utils/colors';
import { IncidentTimelineSkeleton } from '@/components/SkeletonLoaders';
import {
  ShieldAlert, AlertTriangle, Clock, ArrowRight, X, ChevronDown,
  ChevronUp, Shield, Activity, Network, Filter,
  Shield, ShieldCheck, Search,
} from 'lucide-react';

interface IncidentSignal {
  signal_type: string;
  source: string;
  severity: string;
  timestamp: string;
}

interface IncidentDetail {
  id: number;
  ip: string;
  severity: string;
  signal_count: number;
  signal_types: string[];
  sources: string[];
  phases: string[];
  first_seen: string;
  last_seen: string;
  description: string;
  narrative: string;
  metadata: Record<string, any>;
  is_active: boolean;
  auto_resolved: boolean;
  signals: IncidentSignal[];
}

interface Incident {
  id: number;
  ip: string;
  severity: string;
  signal_count: number;
  signal_types: string[];
  sources: string[];
  phases: string[];
  first_seen: string;
  last_seen: string;
  description: string;
  narrative: string;
  metadata: Record<string, any>;
  is_active: boolean;
  auto_resolved: boolean;
}

interface IncidentStatsData {
  total_incidents: number;
  active_incidents: number;
  by_severity: Record<string, number>;
  active_by_severity: Record<string, number>;
  by_phase: Record<string, number>;
  top_offending_ips: Array<{ ip: string; incident_count: number }>;
}

const PHASE_STYLES: Record<string, { label: string; color: string; icon: React.ComponentType<{ size?: number }> }> = {
  recon: { label: 'Reconnaissance', color: CYBER.accent, icon: Activity },
  probe: { label: 'Probing', color: CYBER.orange, icon: Search },
  attack: { label: 'Attack', color: CYBER.red, icon: ShieldAlert },
  exploit: { label: 'Exploitation', color: '#ff00ff', icon: AlertTriangle },
};

// ── Attack Chain Visualization ──
function AttackChain({ phases }: { phases: string[] }) {
  if (!phases || phases.length === 0) return null;

  return (
    <div className="flex items-center gap-1">
      {['recon', 'probe', 'attack', 'exploit'].map((phase, i) => {
        const active = phases.includes(phase);
        const style = PHASE_STYLES[phase];
        const Icon = style?.icon || Activity;
        return (
          <div key={phase} className="flex items-center gap-1">
            <div
              className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold font-mono border transition-all ${
                active ? 'border-opacity-100' : 'border-cyber-border/20 text-cyber-textMuted opacity-40'
              }`}
              style={active ? { borderColor: style.color, color: style.color, backgroundColor: `${style.color}10` } : {}}
            >
              <Icon size={10} />
              {style.label}
            </div>
            {i < 3 && <ArrowRight size={12} className="text-cyber-textMuted" />}
          </div>
        );
      })}
    </div>
  );
}

// ── Incident Row ──
function IncidentRow({ incident, onSelect }: { incident: Incident; onSelect: (id: number) => void }) {
  const style = severityStyle(incident.severity);

  return (
    <div
      className="flex items-center gap-3 p-3 border-b border-cyber-border/30 cursor-pointer hover:bg-cyber-panel/50 transition-colors"
      onClick={() => onSelect(incident.id)}
    >
      <div className="flex-shrink-0">
        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: style.color, boxShadow: `0 0 6px ${style.color}` }} />
      </div>
      <span className="px-2 py-0.5 text-xs rounded font-bold uppercase" style={{
        color: style.color,
        backgroundColor: `${style.color}15`,
        border: `1px solid ${style.color}30`,
      }}>
        {incident.severity}
      </span>
      <span className="font-mono text-sm font-bold text-cyber-text">{incident.ip}</span>
      <span className="text-xs text-cyber-textMuted font-mono ml-auto hidden lg:inline">{incident.signal_count} signals</span>
      <span className="text-xs text-cyber-textMuted font-mono hidden lg:inline">{incident.sources?.length || 0} sources</span>
      {incident.auto_resolved && <span className="text-xs text-cyber-textMuted line-through">auto-resolved</span>}
      {!incident.is_active && !incident.auto_resolved && <span className="text-xs text-cyber-green/60">resolved</span>}
    </div>
  );
}

// ── Incident Detail Modal ──
function IncidentDetailModal({ incident, onClose }: { incident: IncidentDetail; onClose: () => void }) {
  const style = severityStyle(incident.severity);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-8 px-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-cyber-panel border border-cyber-border rounded-xl w-full max-w-3xl max-h-[80vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
        style={{ borderColor: `${style.color}40` }}>
        {/* Header */}
        <div className="sticky top-0 bg-cyber-panel border-b border-cyber-border p-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: style.color, boxShadow: `0 0 8px ${style.color}` }} />
            <h3 className="text-lg font-bold text-gradient-cyber">Incident #{incident.id}</h3>
            <span className="font-mono font-bold text-lg" style={{ color: style.color }}>{incident.ip}</span>
          </div>
          <button onClick={onClose} className="text-cyber-textMuted hover:text-cyber-text">
            <X size={20} />
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Severity + Description */}
          <div>
            <span className="px-3 py-1 text-sm rounded font-bold uppercase" style={{
              color: style.color,
              backgroundColor: `${style.color}15`,
              border: `1px solid ${style.color}30`,
            }}>
              {incident.severity}
            </span>
            <p className="text-sm text-cyber-text mt-2">{incident.description}</p>
          </div>

          {/* Narrative */}
          {incident.narrative && (
            <div className="rounded-lg border border-cyber-accent/20 bg-cyber-accent/5 p-4">
              <h4 className="text-xs text-cyber-accent uppercase tracking-wider mb-2 font-semibold">Incident Narrative</h4>
              <p className="text-sm text-cyber-text/90 leading-relaxed">{incident.narrative}</p>
            </div>
          )}

          {/* Attack Chain */}
          <div>
            <h4 className="text-xs text-cyber-textMuted uppercase tracking-wider mb-2">Attack Chain</h4>
            <AttackChain phases={incident.phases} />
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-cyber-darker rounded-lg p-3">
              <span className="text-xs text-cyber-textMuted uppercase">Signals</span>
              <div className="text-lg font-mono font-bold text-cyber-text">{incident.signal_count}</div>
            </div>
            <div className="bg-cyber-darker rounded-lg p-3">
              <span className="text-xs text-cyber-textMuted uppercase">Sources</span>
              <div className="text-lg font-mono font-bold text-cyber-text">{incident.sources?.length || 0}</div>
            </div>
            <div className="bg-cyber-darker rounded-lg p-3">
              <span className="text-xs text-cyber-textMuted uppercase">First Seen</span>
              <div className="text-xs font-mono text-cyber-text">{incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'N/A'}</div>
            </div>
            <div className="bg-cyber-darker rounded-lg p-3">
              <span className="text-xs text-cyber-textMuted uppercase">Last Seen</span>
              <div className="text-xs font-mono text-cyber-text">{incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}</div>
            </div>
          </div>

          {/* Signal Types */}
          {incident.signal_types && incident.signal_types.length > 0 && (
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

          {/* Signal Timeline */}
          {incident.signals && incident.signals.length > 0 && (
            <div>
              <h4 className="text-xs text-cyber-textMuted uppercase tracking-wider mb-2">Signal Timeline</h4>
              <div className="space-y-1 max-h-60 overflow-y-auto">
                {incident.signals.map((s, i) => {
                  const sStyle = severityStyle(s.severity);
                  return (
                    <div key={i} className="flex items-center gap-2 text-xs font-mono py-1 px-2 rounded bg-cyber-darker/50">
                      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: sStyle.color }} />
                      <span style={{ color: sStyle.color }}>{s.severity}</span>
                      <span className="text-cyber-accent">{s.signal_type}</span>
                      <span className="text-cyber-textMuted">[{s.source}]</span>
                      <span className="text-cyber-textMuted ml-auto">{s.timestamp ? new Date(s.timestamp).toLocaleTimeString() : ''}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main Tab ──
export default function IncidentTimelineTab() {
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [showActiveOnly, setShowActiveOnly] = useState(true);

  const { data: incidents = [], isLoading: loadingIncidents } = useQuery<Incident[]>({
    queryKey: ['incidents'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/incidents');
        const json = await res.json();
        return (json.incidents || []) as Incident[];
      } catch { return []; }
    },
    staleTime: 15_000,
  });

  const { data: stats } = useQuery<IncidentStatsData>({
    queryKey: ['incidents-stats'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/incidents/stats');
        return await res.json();
      } catch { return { total_incidents: 0, active_incidents: 0, by_severity: {}, top_offending_ips: [] }; }
    },
    staleTime: 30_000,
  });

  const filtered = useMemo(() => {
    let result = incidents;
    if (showActiveOnly) result = result.filter(i => i.is_active);
    if (filterSeverity !== 'all') result = result.filter(i => i.severity === filterSeverity);
    result.sort((a, b) => {
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (sevOrder[a.severity as keyof typeof sevOrder] ?? 99) - (sevOrder[b.severity as keyof typeof sevOrder] ?? 99);
    });
    return result;
  }, [incidents, filterSeverity, showActiveOnly]);

  const selected = useMemo(() => {
    if (!selectedId) return null;
    const inc = incidents.find(i => i.id === selectedId);
    return inc as IncidentDetail || null;
  }, [selectedId, incidents]);

  const sevCounts = stats?.by_severity || {};

  if (loadingIncidents) return <IncidentTimelineSkeleton />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gradient-cyber">Incident Timeline</h2>
          <p className="text-xs text-cyber-textMuted mt-1">Correlated security incidents with attack chain analysis</p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[
          { label: 'Total', value: stats?.total_incidents || 0, color: CYBER.accent },
          { label: 'Active', value: stats?.active_incidents || 0, color: CYBER.red },
          { label: 'Critical', value: sevCounts['critical'] || 0, color: '#ff00ff' },
          { label: 'High', value: sevCounts['high'] || 0, color: CYBER.red },
          { label: 'Medium', value: sevCounts['medium'] || 0, color: CYBER.orange },
        ].map(c => (
          <div key={c.label} className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
            <span className="text-xs text-cyber-textMuted uppercase">{c.label}</span>
            <div className="text-2xl font-bold font-mono" style={{ color: c.color }}>{c.value}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={() => setShowActiveOnly(!showActiveOnly)}
          className={`px-3 py-1.5 rounded text-xs font-semibold border transition-all ${
            showActiveOnly ? 'border-cyber-accent text-cyber-accent bg-cyber-accent/10' : 'border-cyber-border/30 text-cyber-textMuted'
          }`}
        >
          Active Only
        </button>
        {['all', 'critical', 'high', 'medium', 'low'].map(s => {
          const active = filterSeverity === s;
          const color = s === 'all' ? CYBER.accent : severityStyle(s).color;
          return (
            <button key={s} onClick={() => setFilterSeverity(s)}
              className={`px-3 py-1.5 rounded text-xs font-semibold uppercase border transition-all ${
                active ? 'border-opacity-100' : 'border-cyber-border/30 text-cyber-textMuted'
              }`}
              style={active ? { borderColor: color, color, backgroundColor: `${color}15` } : {}}
            >
              {s} {s !== 'all' ? `(${sevCounts[s] || 0})` : `(${incidents.length})`}
            </button>
          );
        })}
      </div>

      {/* Top Offending IPs */}
      {stats?.top_offending_ips && stats.top_offending_ips.length > 0 && (
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-cyber-text mb-2 flex items-center gap-2">
            <AlertTriangle size={14} style={{ color: CYBER.orange }} /> Top Offending IPs
          </h3>
          <div className="flex flex-wrap gap-2">
            {stats.top_offending_ips.map(ip => (
              <span key={ip.ip} className="px-3 py-1 rounded bg-cyber-darker border border-cyber-border text-xs font-mono text-cyber-text">
                {ip.ip} ({ip.incident_count})
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Incident List */}
      <div className="bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-cyber-textMuted text-sm">
            <ShieldCheck size={48} className="mx-auto mb-4 opacity-50" />
            <p>{incidents.length === 0 ? 'No incidents detected yet. The correlation engine will group related signals into incidents as data flows in.' : 'No incidents match your filters.'}</p>
          </div>
        ) : (
          <>
            {filtered.map(inc => (
              <IncidentRow key={inc.id} incident={inc} onSelect={setSelectedId} />
            ))}
            <div className="p-3 text-center text-xs text-cyber-textMuted border-t border-cyber-border">
              {filtered.length} incident{filtered.length !== 1 ? 's' : ''}
            </div>
          </>
        )}
      </div>

      {/* Detail Modal */}
      {selected && <IncidentDetailModal incident={selected} onClose={() => setSelectedId(null)} />}
    </div>
  );
}
