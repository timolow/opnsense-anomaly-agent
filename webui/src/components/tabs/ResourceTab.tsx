// ═══════════════════════════════════════════════════
// Resource Tab - System resource monitoring
// Memory, CPU, DB size, Disk usage with thresholds
// ═══════════════════════════════════════════════════

import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../../api';
import type { ResourceData } from '../../types';
import { STATUS, statusColor, CYBER } from '../../utils/colors';

// ── Gauge Component ──
function Gauge({ label, value, max, unit, status, icon }: {
  label: string;
  value: number;
  max: number;
  unit: string;
  status?: string;
  icon: string;
}) {
  const pct = Math.min((value / max) * 100, 100);
  const color = statusColor(status);

  // Calculate arc for gauge
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '12px',
      padding: '20px',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '8px',
      flex: '1',
      minWidth: '180px',
    }}>
      {/* Icon */}
      <div style={{ fontSize: '24px' }}>{icon}</div>

      {/* SVG Gauge */}
      <svg width="100" height="60" viewBox="0 0 100 60">
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke="rgba(0, 255, 170, 0.1)"
          strokeWidth="8"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={circumference * 0.25}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
        />
        <circle
          cx="50" cy="50" r={radius}
          fill="none"
          stroke={color.main}
          strokeWidth="8"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={circumference * 0.25 + (strokeDashoffset * 0.75)}
          strokeLinecap="round"
          transform="rotate(-90 50 50)"
          style={{ filter: `drop-shadow(0 0 4px ${color.glow})` }}
        />
      </svg>

      {/* Value */}
      <div style={{
        fontSize: '24px',
        fontWeight: '700',
        color: color.main,
        fontFamily: 'monospace',
      }}>
        {value.toFixed(1)}{unit}
      </div>

      {/* Label */}
      <div style={{
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '1px',
        color: CYBER.textMuted,
              }}>
        {label}
      </div>

      {/* Status Badge */}
      {status && status !== 'ok' && (
        <div style={{
          fontSize: '10px',
          padding: '2px 8px',
          borderRadius: '4px',
          background: color.bg,
          color: color.main,
          border: `1px solid ${color.main}40`,
          textTransform: 'uppercase',
          letterSpacing: '1px',
        }}>
          {status}
        </div>
      )}
    </div>
  );
}

// ── Info Card Component ──
function InfoCard({ label, value, sublabel }: {
  label: string;
  value: string;
  sublabel?: string;
}) {
  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.5)',
      border: '1px solid rgba(0, 255, 170, 0.1)',
      borderRadius: '8px',
      padding: '12px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: '4px',
    }}>
      <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '1px', color: CYBER.textMuted }}>
        {label}
      </div>
      <div style={{ fontSize: '18px', fontWeight: '600', color: CYBER.text, fontFamily: 'monospace' }}>
        {value}
      </div>
      {sublabel && (
        <div style={{ fontSize: '10px', color: CYBER.textMuted }}>
          {sublabel}
        </div>
      )}
    </div>
  );
}

// ── Threshold Indicator ──
function ThresholdBar({ value, warn, crit, label }: {
  value: number;
  warn: number;
  crit: number;
  label: string;
}) {
  const isCrit = value >= crit;
  const isWarn = value >= warn && !isCrit;
  const barColor = isCrit ? CYBER.red : isWarn ? CYBER.orange : CYBER.green;
  const pct = Math.min((value / crit) * 100, 100);

  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between', marginBottom: '4px',
        fontSize: '11px', color: CYBER.textMuted,
      }}>
        <span>{label}</span>
        <span style={{ color: barColor, fontFamily: 'monospace' }}>{value}%</span>
      </div>
      <div style={{
        height: '6px',
        background: 'rgba(0, 255, 170, 0.05)',
        borderRadius: '3px',
        overflow: 'hidden',
        position: 'relative',
      }}>
        {/* Warning marker */}
        <div style={{
          position: 'absolute',
          left: `${(warn / crit) * 100}%`,
          top: 0,
          bottom: 0,
          width: '2px',
          background: CYBER.orange,
          opacity: 0.6,
        }} />
        {/* Fill */}
        <div style={{
          height: '100%',
          width: `${pct}%`,
          background: barColor,
          borderRadius: '3px',
          transition: 'width 0.5s ease',
        }} />
      </div>
      <div style={{
        display: 'flex', justifyContent: 'space-between', fontSize: '9px',
        color: CYBER.textDim, marginTop: '2px',
      }}>
        <span>0%</span>
        <span style={{ color: CYBER.orange }}>Warn: {warn}%</span>
        <span style={{ color: CYBER.red }}>Crit: {crit}%</span>
      </div>
    </div>
  );
}

// ── Main Tab Component ──
export default function ResourceTab() {
  const [data, setData] = useState<ResourceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const result = await api.resources();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch resource data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000); // Refresh every 15s
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        minHeight: '300px', color: CYBER.green, fontFamily: 'monospace',
      }}>
        <div>Initializing resource monitor...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        minHeight: '300px', color: CYBER.red, fontFamily: 'monospace',
      }}>
        <div style={{ textAlign: 'center' }}>
          <div>Error: {error || 'No data'}</div>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              fetchData();
            }}
            className="inline-flex items-center gap-2 px-4 py-2 mt-4 rounded-md bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent font-semibold text-sm hover:bg-cyber-accent/20 transition-all cursor-pointer"
          >
            ↻ Retry
          </button>
        </div>
      </div>
    );
  }

  const { resources } = data;
  const mem = resources.memory;
  const cpu = resources.cpu;
  const load = resources.load_avg;
  const db = resources.db_size;
  const disk = resources.disk;

  const overallStatus = data.status;
  const overallColor = statusColor(overallStatus);

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: '20px',
      padding: '20px',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '16px 20px',
        background: 'rgba(10, 15, 30, 0.8)',
        border: '1px solid rgba(0, 255, 170, 0.15)',
        borderRadius: '12px',
        backdropFilter: 'blur(10px)',
      }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '18px', color: CYBER.text }}>
            Resource Monitoring
          </h2>
          <div style={{ fontSize: '11px', color: CYBER.textMuted, marginTop: '4px' }}>
            Last updated: {new Date(data.timestamp).toLocaleTimeString()}
          </div>
        </div>
        <div style={{
          padding: '6px 16px',
          borderRadius: '8px',
          background: overallColor.bg,
          border: `1px solid ${overallColor.main}40`,
          color: overallColor.main,
          fontWeight: '600',
          textTransform: 'uppercase',
          letterSpacing: '1px',
          fontSize: '12px',
        }}>
          {overallStatus === 'ok' ? '● Healthy' : `● ${overallStatus}`}
        </div>
      </div>

      {/* Warnings Banner */}
      {data.warnings.length > 0 && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(255, 165, 0, 0.08)',
          border: '1px solid rgba(255, 165, 0, 0.3)',
          borderRadius: '8px',
          color: CYBER.orange,
          fontSize: '12px',
          fontFamily: 'monospace',
        }}>
          ⚠ Warnings: {data.warnings.join(' | ')}
        </div>
      )}

      {/* Main Gauges */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '16px',
      }}>
        <Gauge
          label="Memory Usage"
          value={mem.pct_used || 0}
          max={100}
          unit="%"
          status={mem.status}
          icon="💾"
        />
        <Gauge
          label="CPU Usage"
          value={cpu.usage_pct || 0}
          max={100}
          unit="%"
          status={cpu.status}
          icon="⚡"
        />
        <Gauge
          label="Disk Usage"
          value={disk.pct_used || 0}
          max={100}
          unit="%"
          status={disk.status}
          icon="💿"
        />
        <div style={{
          background: 'rgba(10, 15, 30, 0.7)',
          border: '1px solid rgba(0, 255, 170, 0.15)',
          borderRadius: '12px',
          padding: '20px',
          backdropFilter: 'blur(10px)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '8px',
          flex: '1',
          minWidth: '180px',
        }}>
          <div style={{ fontSize: '24px' }}>🗄️</div>
          <div style={{
            fontSize: '24px',
            fontWeight: '700',
            color: statusColor(db.status).main,
            fontFamily: 'monospace',
          }}>
            {db.mb > 1024 ? `${(db.mb / 1024).toFixed(1)} GB` : `${db.mb.toFixed(0)} MB`}
          </div>
          <div style={{
            fontSize: '11px',
            textTransform: 'uppercase',
            letterSpacing: '1px',
            color: CYBER.textMuted,
          }}>
            Database Size
          </div>
          {db.status && db.status !== 'ok' && (
            <div style={{
              fontSize: '10px',
              padding: '2px 8px',
              borderRadius: '4px',
              background: statusColor(db.status).bg,
              color: statusColor(db.status).main,
              border: `1px solid ${statusColor(db.status).main}40`,
              textTransform: 'uppercase',
              letterSpacing: '1px',
            }}>
              {db.status}
            </div>
          )}
        </div>
      </div>

      {/* Threshold Bars */}
      <div style={{
        background: 'rgba(10, 15, 30, 0.7)',
        border: '1px solid rgba(0, 255, 170, 0.15)',
        borderRadius: '12px',
        padding: '20px',
        backdropFilter: 'blur(10px)',
      }}>
        <h3 style={{
          margin: '0 0 16px 0',
          fontSize: '13px',
          color: CYBER.textMuted,
          textTransform: 'uppercase',
          letterSpacing: '1px',
        }}>
          Threshold Monitoring
        </h3>
        <ThresholdBar
          value={mem.pct_used || 0}
          warn={85}
          crit={95}
          label="Memory (Warn: 85% / Critical: 95%)"
        />
        <ThresholdBar
          value={cpu.usage_pct || 0}
          warn={90}
          crit={98}
          label="CPU (Warn: 90% / Critical: 98%)"
        />
        <ThresholdBar
          value={disk.pct_used || 0}
          warn={85}
          crit={95}
          label="Disk (Warn: 85% / Critical: 95%)"
        />
      </div>

      {/* Detailed Info Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '12px',
      }}>
        <InfoCard
          label="Memory Total"
          value={`${(mem.total_mb || 0).toFixed(0)} MB`}
          sublabel={`Free: ${(mem.free_mb || 0).toFixed(0)} MB | Cached: ${(mem.cached_mb || 0).toFixed(0)} MB`}
        />
        <InfoCard
          label="Load Average"
          value={`${load['1m']?.toFixed(2) || 'N/A'}`}
          sublabel={`5m: ${load['5m']?.toFixed(2) || 'N/A'} | 15m: ${load['15m']?.toFixed(2) || 'N/A'}`}
        />
        <InfoCard
          label="Database Size"
          value={db.mb > 1024 ? `${(db.mb / 1024).toFixed(2)} GB` : `${db.mb.toFixed(1)} MB`}
          sublabel={`${db.bytes?.toLocaleString() || 0} bytes`}
        />
        <InfoCard
          label="Disk Space"
          value={`${(disk.free_mb || 0).toFixed(0)} MB free`}
          sublabel={`Total: ${(disk.total_mb || 0).toFixed(0)} MB | Used: ${(disk.used_mb || 0).toFixed(0)} MB`}
        />
      </div>

      {/* Prometheus Metrics Info */}
      <div style={{
        background: 'rgba(10, 15, 30, 0.5)',
        border: '1px solid rgba(0, 255, 170, 0.1)',
        borderRadius: '8px',
        padding: '16px',
        fontSize: '11px',
        color: CYBER.textMuted,
        fontFamily: 'monospace',
      }}>
        <div style={{ marginBottom: '8px', color: CYBER.textMuted, fontWeight: '600' }}>
          Prometheus Metrics Available
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {['agent_memory_usage_bytes', 'agent_memory_usage_pct', 'agent_cpu_usage_pct',
            'agent_load_avg_1m', 'agent_db_size_bytes', 'agent_disk_usage_pct'].map(metric => (
            <code key={metric} style={{
              padding: '2px 8px',
              background: 'rgba(0, 255, 170, 0.05)',
              border: '1px solid rgba(0, 255, 170, 0.15)',
              borderRadius: '4px',
              color: CYBER.green,
            }}>
              {metric}
            </code>
          ))}
        </div>
      </div>
    </div>
  );
}