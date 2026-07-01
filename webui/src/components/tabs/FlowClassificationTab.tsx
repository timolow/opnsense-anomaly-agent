// ═══════════════════════════════════════════════════
// FlowClassificationTab - ML-PIVOT-09
// ML flow classification results with distribution chart,
// flow details table, and filtering.
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import { CYBER } from '@/utils/colors';
import { format_ip } from '@/utils/formatIp';
import CanvasPieChart from '@/components/charts/CanvasPieChart';
import CanvasBarChart from '@/components/charts/CanvasBarChart';
import { FlowClassificationSkeleton } from '@/components/SkeletonLoaders';
import {
  Activity, ShieldCheck, ShieldAlert, ShieldX, Filter, Search,
  ArrowUpRight, Clock, Network, Database, ChevronDown, ChevronUp,
  AlertTriangle, TrendingUp, Network,
} from 'lucide-react';

type ClassificationType = 'GOOD' | 'ABUSIVE' | 'SUSPICIOUS' | 'UNCERTAIN' | string;

interface FlowClassification {
  classification: string;
  confidence: number;
  src_ip?: string;
  dst_ip?: string;
  src_hostname?: string | null;
  dst_hostname?: string | null;
  dst_port?: number;
  protocol?: string;
  rule_name?: string;
  event_count?: number;
  description?: string;
  flow_type?: string;
  timestamp?: string;
  [key: string]: unknown;
}

const CLASS_COLORS: Record<string, { main: string; bg: string; badge: string }> = {
  GOOD: { main: CYBER.green, bg: 'rgba(0,255,136,0.08)', badge: 'bg-green-500/20 text-green-400' },
  ABUSIVE: { main: CYBER.red, bg: 'rgba(255,23,68,0.08)', badge: 'bg-red-500/20 text-red-400' },
  SUSPICIOUS: { main: CYBER.orange, bg: 'rgba(255,120,0,0.08)', badge: 'bg-orange-500/20 text-orange-400' },
  UNCERTAIN: { main: CYBER.accent, bg: 'rgba(0,255,255,0.08)', badge: 'bg-cyan-500/20 text-cyan-400' },
};

function getClassColor(c: string): string {
  const upper = c.toUpperCase();
  if (upper === 'GOOD') return CYBER.green;
  if (upper === 'ABUSIVE') return CYBER.red;
  if (upper === 'SUSPICIOUS') return CYBER.orange;
  return CYBER.accent;
}

// ── Summary Stats ──
function FlowSummary({ items }: { items: FlowClassification[] }) {
  const breakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    items.forEach(f => {
      const c = f.classification?.toUpperCase() || 'UNKNOWN';
      counts[c] = (counts[c] || 0) + 1;
    });
    return counts;
  }, [items]);

  const cards = [
    { label: 'Total Flows', value: items.length.toLocaleString(), icon: Network, color: CYBER.accent },
    { label: 'Good', value: (breakdown['GOOD'] || 0).toLocaleString(), icon: ShieldCheck, color: CYBER.green },
    { label: 'Abusive', value: (breakdown['ABUSIVE'] || 0).toLocaleString(), icon: ShieldX, color: CYBER.red },
    { label: 'Suspicious', value: (breakdown['SUSPICIOUS'] || 0).toLocaleString(), icon: ShieldAlert, color: CYBER.orange },
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

// ── Confidence Bar ──
function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.min((confidence || 0) * 100, 100);
  const color = pct >= 80 ? CYBER.green : pct >= 50 ? CYBER.orange : CYBER.red;
  return (
    <div className="relative w-full h-2 bg-cyber-darker rounded-full overflow-hidden">
      <div className="absolute inset-y-0 left-0 rounded-full"
        style={{ width: `${pct}%`, backgroundColor: color, opacity: 0.8 }}
      />
    </div>
  );
}

// ── Flow Row ──
function FlowRow({ flow }: { flow: FlowClassification }) {
  const [expanded, setExpanded] = useState(false);
  const cls = (flow.classification || 'UNKNOWN').toUpperCase();
  const color = getClassColor(cls);

  return (
    <div className="border-b border-cyber-border/30 hover:bg-cyber-panel/50 transition-colors">
      <div className="flex items-center gap-3 p-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
        <span className={`px-2 py-0.5 text-xs rounded font-bold ${CLASS_COLORS[cls]?.badge || 'bg-cyber-accent/20 text-cyber-accent'}`}>
          {cls}
        </span>
        {flow.src_ip && <span className="font-mono text-sm text-cyber-text">{format_ip(flow.src_ip, flow.src_hostname)}</span>}
        <ArrowUpRight size={12} className="text-cyber-textMuted" />
        {flow.dst_ip && <span className="font-mono text-sm text-cyber-text">{format_ip(flow.dst_ip, flow.dst_hostname)}:{flow.dst_port || '?'}</span>}
        {flow.protocol && <span className="text-xs text-cyber-textMuted font-mono ml-auto">{flow.protocol}</span>}
        <span className="text-xs font-mono" style={{ color }}>{((flow.confidence || 0) * 100).toFixed(0)}%</span>
        {expanded ? <ChevronUp size={14} className="text-cyber-textMuted" /> : <ChevronDown size={14} className="text-cyber-textMuted" />}
      </div>
      {expanded && (
        <div className="px-3 pb-3 space-y-2">
          <ConfidenceBar confidence={flow.confidence || 0} />
          {flow.description && (
            <p className="text-xs text-cyber-textMuted">{flow.description}</p>
          )}
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            {flow.rule_name && (
              <div>
                <span className="text-cyber-textMuted">Rule: </span>
                <span className="text-cyber-text">{flow.rule_name}</span>
              </div>
            )}
            {flow.flow_type && (
              <div>
                <span className="text-cyber-textMuted">Type: </span>
                <span className="text-cyber-text">{flow.flow_type}</span>
              </div>
            )}
            {flow.event_count !== undefined && (
              <div>
                <span className="text-cyber-textMuted">Events: </span>
                <span className="text-cyber-text">{flow.event_count.toLocaleString()}</span>
              </div>
            )}
            {flow.timestamp && (
              <div>
                <span className="text-cyber-textMuted">Time: </span>
                <span className="text-cyber-text">{new Date(flow.timestamp).toLocaleString()}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Tab ──
export default function FlowClassificationTab() {
  const [filter, setFilter] = useState<ClassificationType>('ALL');
  const [sortBy, setSortBy] = useState<'confidence' | 'events'>('confidence');

  const { data: classifications = [], isLoading } = useQuery<FlowClassification[]>({
    queryKey: ['flow-classifications'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/flow-classifications');
        const json = await res.json();
        return (json.classifications || json.items || json.data || []) as FlowClassification[];
      } catch {
        return [];
      }
    },
    staleTime: 30_000,
  });

  const filtered = useMemo(() => {
    let result = classifications;
    if (filter !== 'ALL') {
      result = result.filter(f => (f.classification || '').toUpperCase() === filter.toUpperCase());
    }
    result.sort((a, b) => {
      if (sortBy === 'confidence') return (b.confidence || 0) - (a.confidence || 0);
      return (b.event_count || 0) - (a.event_count || 0);
    });
    return result;
  }, [classifications, filter, sortBy]);

  const chartData = useMemo(() => {
    const counts: Record<string, number> = {};
    classifications.forEach(f => {
      const c = (f.classification || 'UNKNOWN').toUpperCase();
      counts[c] = (counts[c] || 0) + 1;
    });
    return {
      labels: Object.keys(counts),
      values: Object.values(counts),
      colors: Object.keys(counts).map(k => getClassColor(k)),
    };
  }, [classifications]);

  if (isLoading) return <FlowClassificationSkeleton />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gradient-cyber">Flow Classification</h2>
          <p className="text-xs text-cyber-textMuted mt-1">ML-based flow classification with confidence scoring</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={sortBy}
            onChange={e => setSortBy(e.target.value as any)}
            className="bg-cyber-darker border border-cyber-border rounded px-2 py-1 text-xs text-cyber-text font-mono"
          >
            <option value="confidence">Sort by Confidence</option>
            <option value="events">Sort by Events</option>
          </select>
        </div>
      </div>

      {/* Summary */}
      <FlowSummary items={classifications} />

      {/* Chart + Filters Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-cyber-panel border border-cyber-border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
            <TrendingUp size={14} /> Classification Distribution
          </h3>
          {chartData.values.some(v => v > 0) ? (
            <CanvasPieChart
              labels={chartData.labels}
              values={chartData.values}
              colors={chartData.colors}
              size={200}
            />
          ) : (
            <div className="flex items-center justify-center h-48 text-cyber-textMuted text-sm">No classification data</div>
          )}
        </div>

        {/* Filters */}
        <div className="lg:col-span-2">
          <div className="flex items-center gap-2 mb-2">
            <Filter size={14} className="text-cyber-textMuted" />
            <span className="text-xs text-cyber-textMuted uppercase">Classification Filter</span>
          </div>
          <div className="flex gap-2 flex-wrap">
            {['ALL', 'GOOD', 'ABUSIVE', 'SUSPICIOUS', 'UNCERTAIN'].map(f => {
              const active = filter === f;
              const color = f === 'ALL' ? CYBER.accent : getClassColor(f);
              const count = f === 'ALL' ? classifications.length : classifications.filter(x => (x.classification || '').toUpperCase() === f).length;
              return (
                <button key={f} onClick={() => setFilter(f)}
                  className={`px-3 py-1.5 rounded text-xs font-semibold uppercase tracking-wider transition-all border ${
                    active ? 'border-opacity-100' : 'border-cyber-border border-opacity-30 text-cyber-textMuted hover:text-cyber-text'
                  }`}
                  style={active ? { borderColor: color, color, backgroundColor: `${color}15` } : {}}
                >
                  {f} ({count})
                </button>
              );
            })}
          </div>

          {/* Flow List */}
          <div className="mt-4 bg-cyber-panel border border-cyber-border rounded-lg overflow-hidden max-h-[600px] overflow-y-auto">
            {filtered.length === 0 ? (
              <div className="p-12 text-center text-cyber-textMuted text-sm">
                {classifications.length === 0
                  ? 'No flow classifications yet. The ML classifier will start producing results as it processes network flows.'
                  : 'No flows match the current filter.'
                }
              </div>
            ) : (
              filtered.slice(0, 100).map((f, i) => <FlowRow key={i} flow={f} />)
            )}
            {filtered.length > 100 && (
              <div className="p-3 text-center text-xs text-cyber-textMuted border-t border-cyber-border">
                Showing 100 of {filtered.length} results
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
