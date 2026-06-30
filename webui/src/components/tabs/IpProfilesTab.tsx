// ═══════════════════════════════════════════════════
// IpProfilesTab - ML-PIVOT-08
// IP behavior profiles with threat scores, filtering,
// and expandable detail views.
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { BehaviorProfile, BehaviorLevel } from '@/types';
import { CYBER } from '@/utils/colors';
import CanvasBarChart from '@/components/charts/CanvasBarChart';
import { IpProfilesSkeleton } from '@/components/SkeletonLoaders';
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX, Search, ChevronDown,
  ChevronUp, Clock, Network, AlertTriangle, TrendingUp,
  Filter, RefreshCw, X,
} from 'lucide-react';

const LEVEL_ICONS: Record<BehaviorLevel, React.ComponentType<{ size?: number }>> = {
  benign: ShieldCheck,
  suspicious: ShieldAlert,
  hostile: ShieldX,
  info: Shield,
};

const LEVEL_COLORS: Record<BehaviorLevel, { main: string; bg: string; border: string; badge: string }> = {
  benign: { main: CYBER.green, bg: 'rgba(0,255,136,0.08)', border: CYBER.green, badge: 'bg-green-500/20 text-green-400' },
  suspicious: { main: CYBER.orange, bg: 'rgba(255,120,0,0.08)', border: CYBER.orange, badge: 'bg-orange-500/20 text-orange-400' },
  hostile: { main: CYBER.red, bg: 'rgba(255,23,68,0.08)', border: CYBER.red, badge: 'bg-red-500/20 text-red-400' },
  info: { main: CYBER.accent, bg: 'rgba(0,194,255,0.08)', border: CYBER.accent, badge: 'bg-cyan-500/20 text-cyan-400' },
};

function threatScoreColor(score: number): string {
  if (score >= 75) return CYBER.red;
  if (score >= 50) return CYBER.orange;
  return CYBER.green;
}

function threatLevel(score: number): BehaviorLevel {
  if (score >= 75) return 'hostile';
  if (score >= 50) return 'suspicious';
  return 'benign';
}

function getLevelFromProfile(profile: BehaviorProfile): BehaviorLevel {
  const level = profile.threat_level as BehaviorLevel;
  if (level === 'info') return 'info';
  if (level === 'suspicious') return 'suspicious';
  if (level === 'hostile') return 'hostile';
  return 'benign';
}

// ── Summary Stats Row ──
function IpProfilesSummary({ profiles }: { profiles: BehaviorProfile[] }) {
  const breakdown = useMemo(() => {
    const total = profiles.length;
    const hostile = profiles.filter(p => p.threat_level === 'hostile').length;
    const suspicious = profiles.filter(p => p.threat_level === 'suspicious').length;
    const benign = total - hostile - suspicious;
    return { total, hostile, suspicious, benign };
  }, [profiles]);

  const cards = [
    { label: 'Total Profiles', value: breakdown.total.toLocaleString(), icon: Network, color: CYBER.accent },
    { label: 'Hostile', value: breakdown.hostile.toLocaleString(), icon: ShieldX, color: CYBER.red },
    { label: 'Suspicious', value: breakdown.suspicious.toLocaleString(), icon: ShieldAlert, color: CYBER.orange },
    { label: 'Benign', value: breakdown.benign.toLocaleString(), icon: ShieldCheck, color: CYBER.green },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map(c => {
        const Icon = c.icon;
        return (
          <div key={c.label} className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">{c.label}</span>
              <Icon size={14} style={{ color: c.color }} />
            </div>
            <div className="text-2xl font-bold font-mono" style={{ color: c.color }}>{c.value}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Distribution Chart ──
function IpDistributionChart({ profiles }: { profiles: BehaviorProfile[] }) {
  const data = useMemo(() => {
    const hostile = profiles.filter(p => p.threat_level === 'hostile').length;
    const suspicious = profiles.filter(p => p.threat_level === 'suspicious').length;
    const benign = profiles.filter(p => p.threat_level === 'benign').length;
    return {
      labels: ['Hostile', 'Suspicious', 'Benign'],
      values: [hostile, suspicious, benign],
      colors: [CYBER.red, CYBER.orange, CYBER.green],
    };
  }, [profiles]);

  if (data.values.every(v => v === 0)) return null;

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
      <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
        <TrendingUp size={14} /> Threat Distribution
      </h3>
      <CanvasBarChart
        data={data.values}
        labels={data.labels}
        colors={data.colors}
        height={150}
        showValues
        horizontal={false}
      />
    </div>
  );
}

// ── Score Gauge ──
function ScoreGauge({ score }: { score: number }) {
  const color = threatScoreColor(score);
  const pct = Math.min(score, 100);
  return (
    <div className="relative w-full h-3 bg-cyber-darker rounded-full overflow-hidden">
      <div
        className="absolute inset-y-0 left-0 rounded-full transition-all"
        style={{ width: `${pct}%`, backgroundColor: color, opacity: 0.8 }}
      />
      <span className="absolute inset-0 flex items-center justify-center text-xs font-mono font-bold" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

// ── Profile Card ──
function ProfileCard({ profile }: { profile: BehaviorProfile }) {
  const [expanded, setExpanded] = useState(false);
  const level = profile.threat_level || threatLevel(profile.behavior_score);
  const levelStyle = LEVEL_COLORS[level] || LEVEL_COLORS.benign;
  const LevelIcon = LEVEL_ICONS[level] || Shield;

  return (
    <div className="bg-cyber-panel border rounded-lg overflow-hidden transition-all hover:border-opacity-100"
      style={{ borderColor: levelStyle.border, borderWidth: '1px', borderOpacity: 0.3 }}>
      <div className="p-4 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <LevelIcon size={20} style={{ color: levelStyle.main }} />
            <div>
              <span className="font-mono font-bold text-base" style={{ color: CYBER.text }}>{profile.ip}</span>
              <span className={`ml-2 px-2 py-0.5 text-xs rounded-full font-semibold ${levelStyle.badge}`}>
                {level.toUpperCase()}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-cyber-textMuted font-mono">Score: {profile.behavior_score}</span>
            {expanded ? <ChevronUp size={16} className="text-cyber-textMuted" /> : <ChevronDown size={16} className="text-cyber-textMuted" />}
          </div>
        </div>
        <ScoreGauge score={profile.behavior_score} />
        <div className="flex gap-4 mt-3 text-xs text-cyber-textMuted font-mono">
          <span className="flex items-center gap-1"><Network size={12} /> {profile.event_count_24h?.toLocaleString() || 0} events</span>
          <span className="flex items-center gap-1"><Network size={12} /> {profile.unique_ports || 0} ports</span>
          <span className="flex items-center gap-1"><Clock size={12} /> {profile.last_seen ? new Date(profile.last_seen).toLocaleString() : 'N/A'}</span>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-cyber-border p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-cyber-textMuted text-xs uppercase">Classification</span>
              <div className="font-mono font-bold" style={{ color: levelStyle.main }}>{profile.classification || 'UNKNOWN'}</div>
            </div>
            <div>
              <span className="text-cyber-textMuted text-xs uppercase">First Seen</span>
              <div className="font-mono text-xs">{profile.first_seen ? new Date(profile.first_seen).toLocaleString() : 'N/A'}</div>
            </div>
            <div>
              <span className="text-cyber-textMuted text-xs uppercase">Blocked</span>
              <div className="font-mono" style={{ color: CYBER.red }}>{profile.blocked_count?.toLocaleString() || 0}</div>
            </div>
            <div>
              <span className="text-cyber-textMuted text-xs uppercase">Passed</span>
              <div className="font-mono" style={{ color: CYBER.green }}>{profile.passed_count?.toLocaleString() || 0}</div>
            </div>
          </div>
          {profile.top_rules && profile.top_rules.length > 0 && (
            <div>
              <span className="text-cyber-textMuted text-xs uppercase">Top Rules</span>
              <div className="mt-1 space-y-1">
                {profile.top_rules.slice(0, 5).map((r, i) => (
                  <div key={i} className="flex justify-between text-xs font-mono">
                    <span className="text-cyber-text truncate">{r.rule}</span>
                    <span className="text-cyber-textMuted ml-2">{r.count.toLocaleString()}</span>
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

// ── Main Tab ──
export default function IpProfilesTab() {
  const [filter, setFilter] = useState<BehaviorLevel | 'all'>('all');
  const [search, setSearch] = useState('');

  const { data: profiles = [], isLoading } = useQuery<BehaviorProfile[]>({
    queryKey: ['behavior-profiles'],
    queryFn: async () => {
      const res = await api.behaviorProfiles();
      return res || [];
    },
    staleTime: 30_000,
  });

  const filtered = useMemo(() => {
    let result = profiles;
    if (filter !== 'all') {
      result = result.filter(p => p.threat_level === filter);
    }
    if (search) {
      result = result.filter(p => p.ip.toLowerCase().includes(search.toLowerCase()));
    }
    return result.sort((a, b) => (b.behavior_score || 0) - (a.behavior_score || 0));
  }, [profiles, filter, search]);

  if (isLoading) return <IpProfilesSkeleton />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gradient-cyber">IP Profiles</h2>
          <p className="text-xs text-cyber-textMuted mt-1">Behavioral profiles for tracked IPs with threat scoring</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
            <input
              type="text"
              placeholder="Search IP..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-cyber-darker border border-cyber-border rounded pl-8 pr-3 py-1.5 text-sm text-cyber-text font-mono placeholder-cyber-textMuted focus:outline-none focus:border-cyber-accent"
            />
          </div>
        </div>
      </div>

      {/* Summary */}
      <IpProfilesSummary profiles={profiles} />

      {/* Filters + Chart Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <div className="flex items-center gap-2 mb-2">
            <Filter size={14} className="text-cyber-textMuted" />
            <span className="text-xs text-cyber-textMuted uppercase">Filter</span>
          </div>
          <div className="flex gap-2 flex-wrap">
            {(['all', 'hostile', 'suspicious', 'benign'] as const).map(f => {
              const active = filter === f;
              const color = f === 'all' ? CYBER.accent : LEVEL_COLORS[f]?.main || CYBER.accent;
              return (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 rounded text-xs font-semibold uppercase tracking-wider transition-all border ${
                    active ? 'border-opacity-100' : 'border-cyber-border border-opacity-30 text-cyber-textMuted hover:text-cyber-text'
                  }`}
                  style={active ? { borderColor: color, color, backgroundColor: `${color}15` } : {}}
                >
                  {f === 'all' ? `All (${profiles.length})` : `${f} (${profiles.filter(p => p.threat_level === f).length})`}
                </button>
              );
            })}
          </div>
        </div>
        <IpDistributionChart profiles={profiles} />
      </div>

      {/* Results */}
      {filtered.length === 0 ? (
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-12 text-center">
          <Shield size={48} className="mx-auto mb-4 text-cyber-textMuted opacity-50" />
          <p className="text-cyber-textMuted text-sm">
            {profiles.length === 0 ? 'No IP profiles available yet. Behavioral analysis will populate as events are processed.' : 'No profiles match your filter.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {filtered.map(p => <ProfileCard key={p.ip} profile={p} />)}
        </div>
      )}
    </div>
  );
}
