// =================================================================
// Alert Detail Panel with Suggested Actions (Runbook)
// =================================================================
// Slides in from the right when an alert row is clicked. Shows:
// - Full alert details
// - Runbook-based suggested actions
// - Action feedback (success/error toasts)
// =================================================================

import React, { useState, useCallback, useEffect } from 'react';
import {
  X, ShieldAlert, Clock, MapPin, Server, FileText,
  ChevronRight, AlertTriangle, CheckCircle, AlertCircle,
  Lightbulb, BookOpen, Zap,
} from 'lucide-react';
import { getRunbook, normalizeAlertType, type RunbookAction } from '@/data/runbooks';
import type { AlertsData } from '@/types';

interface AlertDetailPanelProps {
  alert: AlertsData['anomalies'][0] | null;
  onClose: () => void;
}

export function AlertDetailPanel({ alert, onClose }: AlertDetailPanelProps) {
  const [actionResults, setActionResults] = useState<Record<number, { loading: boolean; ok?: boolean; message?: string }>>({});
  const [instructionOpen, setInstructionOpen] = useState<number | null>(null);

  // Reset state when alert changes
  useEffect(() => {
    setActionResults({});
    setInstructionOpen(null);
  }, [alert]);

  if (!alert) return null;

  const alertType = normalizeAlertType(alert.type);
  const runbook = getRunbook(alertType);

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-cyber-red';
      case 'HIGH': return 'text-cyber-orange';
      case 'MEDIUM': return 'text-cyber-yellow';
      default: return 'text-cyber-green';
    }
  };

  const severityBg = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-cyber-red/10 border-cyber-red/40';
      case 'HIGH': return 'bg-cyber-orange/10 border-cyber-orange/40';
      case 'MEDIUM': return 'bg-cyber-yellow/10 border-cyber-yellow/40';
      default: return 'bg-cyber-green/10 border-cyber-green/40';
    }
  };

  const handleAction = useCallback(async (action: RunbookAction, index: number) => {
    if (action.kind !== 'inline' || !action.execute) return;

    setActionResults(prev => ({ ...prev, [index]: { loading: true } }));
    try {
      const result = await action.execute(alert);
      setActionResults(prev => ({
        ...prev,
        [index]: { loading: false, ok: result.ok, message: result.message },
      }));
    } catch {
      setActionResults(prev => ({
        ...prev,
        [index]: { loading: false, ok: false, message: 'Action failed unexpectedly' },
      }));
    }
  }, [alert]);

  const sortedActions = [...runbook.actions].sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99));

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
        onClick={onClose}
      />

      {/* Slide-in panel */}
      <div className="fixed right-0 top-0 h-full w-full max-w-xl bg-[#0d1117] border-l border-cyber-border/50 z-50 overflow-y-auto shadow-[[-10px,0,40px,rgba(0,0,0,0.5)]]">
        {/* ── Header ── */}
        <div className="sticky top-0 z-10 bg-[#0d1117]/95 backdrop-blur border-b border-cyber-border/40 px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center border border-cyber-accent/30 bg-cyber-accent/5">
                <ShieldAlert size={20} className="text-cyber-accent" />
              </div>
              <div>
                <h2 className="text-base font-bold font-mono text-cyber-text">Alert Details</h2>
                <p className="text-xs text-cyber-textMuted font-mono">Runbook &amp; Suggested Actions</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-md border border-cyber-border/40 flex items-center justify-center hover:border-cyber-accent/60 hover:text-cyber-accent transition-colors text-cyber-textMuted"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* ── Alert Summary ── */}
          <div className={`rounded-lg border p-4 ${severityBg(alert.severity)}`}>
            <div className="flex items-start gap-3">
              <AlertTriangle size={20} className={`${severityColor(alert.severity)} mt-0.5 flex-shrink-0`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`cyber-badge ${severityColor(alert.severity)} border`}>
                    {alert.severity}
                  </span>
                  <span className="font-bold font-mono text-cyber-text">{alert.type}</span>
                </div>
                <p className="text-sm text-cyber-text/80">{runbook.summary}</p>
              </div>
            </div>
          </div>

          {/* ── Alert Details Grid ── */}
          <div className="grid grid-cols-2 gap-3">
            <DetailField icon={<Clock size={14} />} label="Time" value={alert.timestamp} />
            <DetailField icon={<MapPin size={14} />} label="Source IP" value={alert.source_ip} />
            {alert.destination_ip && (
              <DetailField icon={<Server size={14} />} label="Destination" value={alert.destination_ip} />
            )}
            <DetailField icon={<FileText size={14} />} label="Category" value={alert.category} />
          </div>

          {/* ── Details text ── */}
          {alert.details && (
            <div className="cyber-card p-3">
              <p className="text-xs text-cyber-textMuted mb-1 font-mono">DETAILS</p>
              <p className="text-sm font-mono text-cyber-text/90">{alert.details}</p>
            </div>
          )}

          {/* ── Escalation note ── */}
          {runbook.escalation && (
            <div className="rounded-lg border border-cyber-orange/30 bg-cyber-orange/5 p-3">
              <div className="flex items-start gap-2">
                <AlertTriangle size={16} className="text-cyber-orange mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-mono text-cyber-orange font-semibold mb-1">ESCALATION</p>
                  <p className="text-sm text-cyber-text/80">{runbook.escalation}</p>
                </div>
              </div>
            </div>
          )}

          {/* ── Suggested Actions ── */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <BookOpen size={16} className="text-cyber-cyan" />
              <h3 className="text-sm font-bold font-mono text-cyber-cyan">SUGGESTED ACTIONS</h3>
              <span className="text-xs text-cyber-textMuted font-mono">({sortedActions.length} actions)</span>
            </div>

            <div className="space-y-2">
              {sortedActions.map((action, index) => {
                const result = actionResults[index];
                const isInline = action.kind === 'inline';
                const isInstruction = action.kind === 'instruction';
                const isInstructionOpen = instructionOpen === index;

                return (
                  <div key={index}>
                    <div className={`rounded-lg border transition-all ${
                      result?.ok
                        ? 'border-cyber-green/50 bg-cyber-green/5'
                        : result?.ok === false
                        ? 'border-cyber-red/50 bg-cyber-red/5'
                        : 'border-cyber-border/30 bg-cyber-panel/40'
                    }`}>
                      <div className="p-3">
                        {/* Action header */}
                        <div className="flex items-center gap-2 mb-1">
                          {action.icon && <span className="text-sm">{action.icon}</span>}
                          <span className={`text-xs font-mono ${isInline ? 'text-cyber-cyan' : 'text-cyber-textMuted'}`}>
                            {action.priority === 0 ? 'PRIMARY' : `STEP ${action.priority || index + 1}`}
                          </span>
                          <span className="text-sm font-semibold text-cyber-text flex-1">{action.label}</span>
                          {result?.ok === true && <CheckCircle size={14} className="text-cyber-green flex-shrink-0" />}
                          {result?.ok === false && <AlertCircle size={14} className="text-cyber-red flex-shrink-0" />}
                        </div>

                        {/* Inline action button */}
                        {isInline && (
                          <button
                            onClick={() => handleAction(action, index)}
                            disabled={result?.loading}
                            className={`mt-2 w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md font-mono text-xs transition-all ${
                              result?.loading
                                ? 'bg-cyber-accent/20 text-cyber-accent/60 cursor-wait'
                                : 'bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent hover:bg-cyber-accent/20 hover:shadow-neon-cyan'
                            }`}
                          >
                            {result?.loading ? (
                              <span className="animate-pulse">Executing...</span>
                            ) : (
                              <>
                                <Zap size={12} />
                                Execute Action
                              </>
                            )}
                          </button>
                        )}

                        {/* Instructional action (expandable) */}
                        {isInstruction && (
                          <div>
                            <button
                              onClick={() => setInstructionOpen(isInstructionOpen ? null : index)}
                              className="flex items-center gap-1 text-xs font-mono text-cyber-textMuted hover:text-cyber-accent transition-colors mt-2"
                            >
                              <ChevronRight size={12} className={`transition-transform ${isInstructionOpen ? 'rotate-90' : ''}`} />
                              {isInstructionOpen ? 'Hide instructions' : 'Show instructions'}
                            </button>
                            {isInstructionOpen && action.instruction && (
                              <div className="mt-2 p-3 rounded-md bg-[#0a0e17] border border-cyber-border/30 font-mono text-xs text-cyber-text/80 whitespace-pre-wrap leading-relaxed">
                                {action.instruction}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Result feedback */}
                        {result?.ok === false && result?.message && (
                          <div className="mt-2 text-xs text-cyber-red font-mono">
                            {result.message}
                          </div>
                        )}
                        {result?.ok === true && result?.message && (
                          <div className="mt-2 text-xs text-cyber-green font-mono">
                            {result.message}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ── Footer ── */}
          <div className="pt-4 border-t border-cyber-border/30">
            <div className="flex items-center gap-2 text-xs text-cyber-textMuted font-mono">
              <Lightbulb size={12} className="text-cyber-yellow" />
              Actions are suggested based on alert type. Verify before executing.
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Sub-components ────────────────────────────────────────────────

function DetailField({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-cyber-border/30 bg-cyber-panel/40 p-3">
      <div className="flex items-center gap-1.5 text-xs text-cyber-textMuted mb-1">
        {icon}
        <span className="font-mono">{label}</span>
      </div>
      <p className="text-sm font-mono text-cyber-text truncate">{value || '—'}</p>
    </div>
  );
}