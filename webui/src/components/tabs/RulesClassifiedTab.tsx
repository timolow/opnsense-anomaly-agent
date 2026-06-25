// ═══════════════════════════════════════════════════
// Rules Classified ML Tab - ML rule classification
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { RulesClassifiedData } from '@/types';
import { TrendingUp, Brain, Target, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import { CLASSIFICATION, RECHARTS_TOOLTIP, CYBER } from '@/utils/colors';

import { RulesClassifiedSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function RulesClassifiedTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<RulesClassifiedData>({
    queryKey: ['rules-classified'],
    queryFn: () => api.rulesClassified(false),
    refetchInterval: 60000,
  });

  const [refresh, setRefresh] = useState(false);

  if (isLoading) return <RulesClassifiedSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Rules ML" />;

  const pieData = [
    { name: 'GOOD', value: data.summary.good, color: CLASSIFICATION.GOOD },
    { name: 'ABUSIVE', value: data.summary.abusive, color: CLASSIFICATION.ABUSIVE },
    { name: 'HIGH', value: data.summary.high_traffic, color: CLASSIFICATION.HIGH_TRAFFIC },
    { name: 'LOW', value: data.summary.low_traffic, color: CLASSIFICATION.LOW_TRAFFIC },
  ];

  const classificationColor = (c: string) => {
    switch (c) {
      case 'GOOD': return 'cyber-badge-pass';
      case 'ABUSIVE': return 'cyber-badge-block';
      case 'HIGH_TRAFFIC': return 'cyber-badge-info';
      case 'LOW_TRAFFIC': return 'cyber-badge-warning';
      default: return 'cyber-badge-info';
    }
  };

  const refreshRules = async () => {
    setRefresh(true);
    await api.rulesClassified(true);
    setRefresh(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <Brain size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Rules Machine Learning</h2>
          <span className="text-xs text-cyber-textMuted font-mono">Adaptive Classification</span>
        </div>
        <button
          onClick={refreshRules}
          className="cyber-btn-purple flex items-center gap-2"
          disabled={refresh}
        >
          <TrendingUp size={14} /> {refresh ? 'Processing...' : 'Reclassify'}
        </button>
      </div>

      {/* ML Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Brain size={14} className="text-cyber-purple" />
            <span className="cyber-stat-label">Rules Trained</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-purple">{data.summary.total}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 size={14} className="text-cyber-green" />
            <span className="cyber-stat-label">GOOD</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-green">{data.summary.good}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-cyber-red" />
            <span className="cyber-stat-label">ABUSIVE</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-red">{data.summary.abusive}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Target size={14} className="text-cyber-accent" />
            <span className="cyber-stat-label">Self-Learning</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-cyan">
            {data.ml_stats?.self_learning_enabled ? 'ON' : 'OFF'}
          </div>
        </div>
      </div>

      {/* ML Stats & Pie Chart */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="cyber-card p-4 scanlines">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Classification Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={pieData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={80}
                innerRadius={50}
                strokeWidth={2}
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.color}60)` }} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={RECHARTS_TOOLTIP}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 mt-2">
            {pieData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                <span className="text-xs text-cyber-textMuted">{d.name}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="cyber-card p-4 scanlines">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Model Parameters</h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-xs text-cyber-textMuted">Portscan Threshold</span>
                <span className="text-xs font-mono">{data.ml_stats?.portscan_threshold || 5}</span>
              </div>
              <div className="cyber-progress-track">
                <div className="cyber-progress-fill bg-cyber-accent" style={{ width: '60%' }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-xs text-cyber-textMuted">Bruteforce Threshold</span>
                <span className="text-xs font-mono">{data.ml_stats?.bruteforce_threshold || 50}</span>
              </div>
              <div className="cyber-progress-track">
                <div className="cyber-progress-fill bg-cyber-pink" style={{ width: '45%' }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-xs text-cyber-textMuted">Sensitivity</span>
                <span className={`font-mono text-xs ${
                  data.ml_stats?.sensitivity === 'high' ? 'text-cyber-red' :
                  data.ml_stats?.sensitivity === 'medium' ? 'text-cyber-yellow' : 'text-cyber-green'
                }`}>{data.ml_stats?.sensitivity || 'medium'}</span>
              </div>
            </div>
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-xs text-cyber-textMuted">Events Processed</span>
                <span className="text-xs font-mono">{(data.ml_stats?.events_processed || 0).toLocaleString() || '0'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Classified Rules</h3>
        <div className="cyber-table-responsive"><table className="cyber-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Source</th>
              <th>Events 24h</th>
              <th>Classification</th>
              <th>Confidence</th>
              <th>ML Label</th>
            </tr>
          </thead>
          <tbody>
            {data.rules.slice(0, 30).map((rule) => (
              <tr key={rule.uuid} className="hover:bg-cyber-panel/30">
                <td className="font-semibold max-w-[150px] truncate">{rule.name}</td>
                <td className="font-mono text-xs">{rule.source_net}</td>
                <td className="font-mono">{(rule.events_24h || 0).toLocaleString()}</td>
                <td><span className={`cyber-badge ${classificationColor(rule.classification)}`}>{rule.classification}</span></td>
                <td>
                  <div className="flex items-center gap-1">
                    <div className="cyber-progress-track w-16">
                      <div className="cyber-progress-fill bg-cyber-accent" style={{ width: `${rule.confidence}%` }} />
                    </div>
                    <span className="font-mono text-xs">{rule.confidence}%</span>
                  </div>
                </td>
                <td>
                  {rule.ml_label ? (
                    <span className={`cyber-badge ${
                      rule.ml_label === 'GOOD' ? 'cyber-badge-pass' : 'cyber-badge-block'
                    }`}>{rule.ml_label}</span>
                  ) : (
                    <span className="text-xs text-cyber-textMuted">Pending</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
