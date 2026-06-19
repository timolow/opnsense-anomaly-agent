// ═══════════════════════════════════════════════════
// Rules Tab - Firewall rules
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { RulesClassifiedData } from '@/types';
import { Layers, Search, ThumbsUp, ThumbsDown, MessageSquare } from 'lucide-react';
import { useState } from 'react';

export default function RulesTab() {
  const { data } = useQuery<RulesClassifiedData>({
    queryKey: ['rules-classified'],
    queryFn: () => api.rulesClassified(false),
    refetchInterval: 60000,
  });

  const [filter, setFilter] = useState('');
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [feedback, setFeedback] = useState({ label: 'GOOD', reason: '' });

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const filtered = data.rules.filter((r) =>
    r.name.toLowerCase().includes(filter.toLowerCase()) ||
    r.source_net.toLowerCase().includes(filter.toLowerCase()) ||
    r.destination_net.toLowerCase().includes(filter.toLowerCase())
  );

  const classificationColor = (c: string) => {
    switch (c) {
      case 'GOOD': return 'cyber-badge-pass';
      case 'ABUSIVE': return 'cyber-badge-block';
      case 'HIGH_TRAFFIC': return 'cyber-badge-info';
      case 'LOW_TRAFFIC': return 'cyber-badge-warning';
      default: return 'cyber-badge-info';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <Layers size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">Firewall Rules</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{data.rules.length} rules</span>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-cyan">{data.summary.total}</div>
          <div className="cyber-stat-label">Total Rules</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-green">{data.summary.good}</div>
          <div className="cyber-stat-label">GOOD</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-red">{data.summary.abusive}</div>
          <div className="cyber-stat-label">ABUSIVE</div>
        </div>
        <div className="cyber-card p-3 cyber-card-hover">
          <div className="text-xl font-bold font-mono text-neon-yellow">{data.summary.high_traffic}</div>
          <div className="cyber-stat-label">High Traffic</div>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
        <input
          type="text"
          placeholder="Search rules..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="cyber-input pl-9"
        />
      </div>

      {/* Rules Table */}
      <div className="cyber-card p-4 scanlines">
        {selectedRule ? (() => {
          const rule = data.rules.find(r => r.uuid === selectedRule);
          if (!rule) return null;
          return (
            <div className="mb-4 p-4 rounded-lg bg-cyber-panelHover border border-cyber-border">
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-bold text-cyber-accent">{rule.name}</h4>
                <button onClick={() => setSelectedRule(null)} className="text-cyber-textMuted hover:text-cyber-text">✕</button>
              </div>
              <div className="grid grid-cols-2 gap-3 mb-4">
                <div><span className="text-xs text-cyber-textMuted">Source</span><div className="font-mono text-sm">{rule.source_net}</div></div>
                <div><span className="text-xs text-cyber-textMuted">Destination</span><div className="font-mono text-sm">{rule.destination_net}</div></div>
                <div><span className="text-xs text-cyber-textMuted">Classification</span><span className={`cyber-badge ${classificationColor(rule.classification)}`}>{rule.classification}</span></div>
                <div><span className="text-xs text-cyber-textMuted">Confidence</span><div className="font-mono text-sm">{rule.confidence}%</div></div>
              </div>
              {rule.ml_label && (
                <div className="mb-3 p-2 rounded bg-cyber-darker border border-cyber-border">
                  <div className="text-xs text-cyber-textMuted mb-1">ML Classification</div>
                  <div className="font-mono text-sm">{rule.ml_label}</div>
                  {rule.ml_reason && <div className="text-xs text-cyber-textMuted mt-1">{rule.ml_reason}</div>}
                </div>
              )}
              <div className="flex gap-2">
                <button
                  onClick={() => api.submitFeedback({ rule_name: rule.name, label: 'GOOD', reason: feedback.reason, user_id: 'web' })}
                  className="cyber-btn-success flex items-center gap-1"
                >
                  <ThumbsUp size={12} /> Mark GOOD
                </button>
                <button
                  onClick={() => api.submitFeedback({ rule_name: rule.name, label: 'ABUSIVE', reason: feedback.reason, user_id: 'web' })}
                  className="cyber-btn-danger flex items-center gap-1"
                >
                  <ThumbsDown size={12} /> Mark ABUSIVE
                </button>
                <input
                  type="text"
                  placeholder="Reason..."
                  value={feedback.reason}
                  onChange={(e) => setFeedback({ ...feedback, reason: e.target.value })}
                  className="cyber-input flex-1 text-xs"
                />
              </div>
            </div>
          );
        })() : null}

        <table className="cyber-table">
          <thead>
            <tr>
              <th>Rule Name</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Events 24h</th>
              <th>Classification</th>
              <th>Confidence</th>
              <th>Feedback</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map((rule) => (
              <tr
                key={rule.uuid}
                className="cursor-pointer hover:bg-cyber-panel/30"
                onClick={() => setSelectedRule(rule.uuid === selectedRule ? null : rule.uuid)}
              >
                <td className="font-semibold">{rule.name}</td>
                <td className="font-mono text-xs">{rule.source_net}</td>
                <td className="font-mono text-xs">{rule.destination_net}</td>
                <td className="font-mono">{rule.events_24h.toLocaleString()}</td>
                <td><span className={`cyber-badge ${classificationColor(rule.classification)}`}>{rule.classification}</span></td>
                <td>
                  <div className="flex items-center gap-1">
                    <div className="cyber-progress-track w-16">
                      <div
                        className="cyber-progress-fill bg-cyber-accent"
                        style={{ width: `${rule.confidence}%` }}
                      />
                    </div>
                    <span className="font-mono text-xs">{rule.confidence}%</span>
                  </div>
                </td>
                <td className="text-xs text-cyber-textMuted">{rule.feedback_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
