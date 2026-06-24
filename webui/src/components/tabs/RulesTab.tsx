// ═══════════════════════════════════════════════════
// Rules Tab - Firewall rules with inline ML feedback
// ═══════════════════════════════════════════════════

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import type { RulesClassifiedData } from '@/types';
import { Layers, Search, ThumbsUp, ThumbsDown, AlertTriangle, Lightbulb, CheckCircle, XCircle } from 'lucide-react';
import { useState, useCallback } from 'react';

export default function RulesTab() {
  const queryClient = useQueryClient();
  const { data } = useQuery<RulesClassifiedData>({
    queryKey: ['rules-classified'],
    queryFn: () => api.rulesClassified(false),
    refetchInterval: 60000,
  });

  const [filter, setFilter] = useState('');
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [feedback, setFeedback] = useState({ label: 'GOOD', reason: '' });
  const [feedbackFlash, setFeedbackFlash] = useState<Record<string, { label: string; ts: number }>>({});

  // Feedback mutation with optimistic refetch
  const submitFeedback = useMutation({
    mutationFn: (params: { ruleName: string; label: string }) =>
      api.submitFeedback({ rule_name: params.ruleName, label: params.label, reason: '', user_id: 'web' }),
    onSuccess: (_, vars) => {
      const key = vars.ruleName;
      setFeedbackFlash(prev => ({ ...prev, [key]: { label: vars.label, ts: Date.now() } }));
      // Clear flash after 2s
      setTimeout(() => {
        setFeedbackFlash(prev => {
          const next = { ...prev };
          delete next[key];
          return next;
        });
      }, 2000);
      // Refetch rules data to pick up updated classification
      queryClient.invalidateQueries({ queryKey: ['rules-classified'] });
    },
  });

  const handleInlineFeedback = useCallback((ruleName: string, label: string) => {
    if (submitFeedback.isPending) return;
    submitFeedback.mutate({ ruleName, label });
  }, [submitFeedback]);

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const filtered = data.rules.filter((r) =>
    r.name.toLowerCase().includes(filter.toLowerCase()) ||
    r.source_net.toLowerCase().includes(filter.toLowerCase()) ||
    r.destination_net.toLowerCase().includes(filter.toLowerCase())
  );

  const uncertainCount = data.summary.uncertain || data.rules.filter(r => r.classification === 'UNCERTAIN').length;

  const classificationColor = (c: string) => {
    switch (c) {
      case 'GOOD': return 'cyber-badge-pass';
      case 'ABUSIVE': return 'cyber-badge-block';
      case 'HIGH_TRAFFIC': return 'cyber-badge-info';
      case 'LOW_TRAFFIC': return 'cyber-badge-warning';
      case 'UNCERTAIN': return 'cyber-badge-warning';
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

      {/* ── UNCERTAIN Feedback Banner ── */}
      {uncertainCount > 0 && (
        <div className="relative overflow-hidden rounded-lg border border-yellow-500/30 bg-gradient-to-r from-yellow-500/5 via-yellow-500/10 to-yellow-500/5 p-4">
          {/* Animated glow pulse */}
          <div className="absolute inset-0 bg-yellow-500/5 animate-pulse" />
          <div className="relative flex items-start gap-3">
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center">
              <Lightbulb size={20} className="text-yellow-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-bold text-yellow-400 text-sm">Help Train the ML Classifier</h3>
                <span className="cyber-badge cyber-badge-warning text-xs">{uncertainCount} UNCERTAIN</span>
              </div>
              <p className="text-xs text-cyber-textMuted leading-relaxed">
                {uncertainCount} rule{uncertainCount > 1 ? 's' : ''} have low-confidence classifications. 
                Use the <ThumbsUp size={11} className="inline vertical-middle text-neon-green" /> / <ThumbsDown size={11} className="inline vertical-middle text-neon-red" /> buttons 
                on each row to provide feedback. Each vote helps the ML model learn accurate rule classifications and improve threat detection.
              </p>
              <div className="flex items-center gap-4 mt-2">
                <span className="text-xs font-mono text-yellow-300/70">
                  Classified: {data.summary.good + data.summary.abusive} of {data.summary.total} rules
                </span>
                <div className="flex-1 max-w-xs">
                  <div className="cyber-progress-track h-1.5">
                    <div
                      className="cyber-progress-fill bg-yellow-400 transition-all duration-500"
                      style={{ width: `${data.summary.total > 0 ? ((data.summary.good + data.summary.abusive) / data.summary.total * 100).toFixed(1) : 0}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
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
        <div className={`cyber-card p-3 cyber-card-hover ${uncertainCount > 0 ? 'border-yellow-500/30' : ''}`}>
          <div className="text-xl font-bold font-mono text-yellow-400">{uncertainCount}</div>
          <div className="cyber-stat-label">UNCERTAIN</div>
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
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

        <div className="cyber-table-responsive"><table className="cyber-table">
          <thead>
            <tr>
              <th>Rule Name</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Events 24h</th>
              <th>Classification</th>
              <th>Confidence</th>
              <th>Feedback</th>
              <th>Vote</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map((rule) => {
              const flash = feedbackFlash[rule.name];
              const isFlashing = flash && Date.now() - flash.ts < 2000;
              return (
                <tr
                  key={rule.uuid}
                  className={`cursor-pointer hover:bg-cyber-panel/30 ${
                    rule.classification === 'UNCERTAIN' ? 'bg-yellow-500/3' : ''
                  } ${isFlashing ? (flash.label === 'GOOD' ? 'bg-neon-green/10' : 'bg-neon-red/10') : ''}`}
                  onClick={() => setSelectedRule(rule.uuid === selectedRule ? null : rule.uuid)}
                >
                  <td className="font-semibold">{rule.name}</td>
                  <td className="font-mono text-xs">{rule.source_net}</td>
                  <td className="font-mono text-xs">{rule.destination_net}</td>
                  <td className="font-mono">{(rule.events_24h || 0).toLocaleString()}</td>
                  <td><span className={`cyber-badge ${classificationColor(rule.classification)}`}>{rule.classification}</span></td>
                  <td>
                    <div className="flex items-center gap-1">
                      <div className="cyber-progress-track w-16">
                        <div
                          className={`cyber-progress-fill ${
                            rule.confidence < 40 ? 'bg-yellow-400' : 'bg-cyber-accent'
                          }`}
                          style={{ width: `${rule.confidence}%` }}
                        />
                      </div>
                      <span className="font-mono text-xs">{rule.confidence}%</span>
                    </div>
                  </td>
                  <td className="text-xs text-cyber-textMuted font-mono">{rule.feedback_count || '—'}</td>
                  <td>
                    <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                      {/* Flash feedback indicator */}
                      {isFlashing && (
                        <span className={`mr-1 ${flash.label === 'GOOD' ? 'text-neon-green' : 'text-neon-red'}`}>
                          {flash.label === 'GOOD' ? <CheckCircle size={12} /> : <XCircle size={12} />}
                        </span>
                      )}
                      <button
                        onClick={() => handleInlineFeedback(rule.name, 'GOOD')}
                        title="Mark as GOOD"
                        className={`p-1 rounded transition-colors ${
                          isFlashing && flash.label === 'GOOD'
                            ? 'text-neon-green bg-neon-green/20'
                            : 'text-cyber-textMuted hover:text-neon-green hover:bg-neon-green/10'
                        }`}
                      >
                        <ThumbsUp size={14} />
                      </button>
                      <button
                        onClick={() => handleInlineFeedback(rule.name, 'ABUSIVE')}
                        title="Mark as ABUSIVE"
                        className={`p-1 rounded transition-colors ${
                          isFlashing && flash.label === 'ABUSIVE'
                            ? 'text-neon-red bg-neon-red/20'
                            : 'text-cyber-textMuted hover:text-neon-red hover:bg-neon-red/10'
                        }`}
                      >
                        <ThumbsDown size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
