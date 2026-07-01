// ═══════════════════════════════════════════════════
// ObservabilityTab - Pipeline health metrics
// P7-T6: Throughput, error rates, resources, TimescaleDB, Redis lag
// ═══════════════════════════════════════════════════

import { useRef, useEffect, useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { PipelineHealthData } from '@/types';
import { Activity, Database, Server, HardDrive, AlertTriangle, Wifi, Clock, Gauge, ShieldCheck } from 'lucide-react';

import { TabQueryError } from '../TabShell';

// ── Multi-series Canvas Area Chart ──
interface ChartPoint {
  x: number;
  y1: number;
  y2: number;
  label: string;
}

function ThroughputChart({ data }: { data: ChartPoint[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null);
  const dataRef = useRef(data);
  dataRef.current = data;

  const draw = useCallback((w: number, h: number) => {
    const canvas = canvasRef.current;
    if (!canvas || dataRef.current.length < 2) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const pad = { top: 20, right: 16, bottom: 28, left: 48 };
    const cw = w - pad.left - pad.right;
    const ch = h - pad.top - pad.bottom;

    const allVals = dataRef.current.flatMap((d) => [d.y1, d.y2]);
    const maxVal = Math.max(...allVals, 1);

    // Grid lines
    ctx.strokeStyle = '#1a2332';
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (i / 4) * ch;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();
      // Y labels
      const val = Math.round(maxVal * (1 - i / 4));
      ctx.fillStyle = '#4a5568';
      ctx.font = '10px monospace';
      ctx.textAlign = 'right';
      ctx.fillText(val.toString(), pad.left - 6, y + 3);
    }

    // Build points
    const points1 = dataRef.current.map((d, i) => ({
      x: pad.left + (i / (dataRef.current.length - 1)) * cw,
      y: pad.top + ch - (d.y1 / maxVal) * ch,
      value: d.y1,
      label: d.label,
    }));
    const points2 = dataRef.current.map((d, i) => ({
      x: pad.left + (i / (dataRef.current.length - 1)) * cw,
      y: pad.top + ch - (d.y2 / maxVal) * ch,
      value: d.y2,
      label: d.label,
    }));

    // Store points for hover
    (canvas as any)._points1 = points1;
    (canvas as any)._points2 = points2;

    // Area fill - events (cyan)
    const grad1 = ctx.createLinearGradient(0, pad.top, 0, h - pad.bottom);
    grad1.addColorStop(0, 'rgba(0,229,255,0.25)');
    grad1.addColorStop(1, 'rgba(0,229,255,0.02)');
    ctx.beginPath();
    ctx.moveTo(points1[0].x, points1[0].y);
    points1.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.lineTo(points1[points1.length - 1].x, h - pad.bottom);
    ctx.lineTo(points1[0].x, h - pad.bottom);
    ctx.closePath();
    ctx.fillStyle = grad1;
    ctx.fill();

    // Area fill - anomalies (magenta)
    const grad2 = ctx.createLinearGradient(0, pad.top, 0, h - pad.bottom);
    grad2.addColorStop(0, 'rgba(255,0,128,0.25)');
    grad2.addColorStop(1, 'rgba(255,0,128,0.02)');
    ctx.beginPath();
    ctx.moveTo(points2[0].x, points2[0].y);
    points2.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.lineTo(points2[points2.length - 1].x, h - pad.bottom);
    ctx.lineTo(points2[0].x, h - pad.bottom);
    ctx.closePath();
    ctx.fillStyle = grad2;
    ctx.fill();

    // Line - events
    ctx.beginPath();
    ctx.moveTo(points1[0].x, points1[0].y);
    points1.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = '#00e5ffcc';
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.stroke();

    // Line - anomalies
    ctx.beginPath();
    ctx.moveTo(points2[0].x, points2[0].y);
    points2.forEach((p) => ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = '#ff0080cc';
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.stroke();

    // X-axis labels (every ~10th point)
    ctx.fillStyle = '#4a5568';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(dataRef.current.length / 6));
    dataRef.current.forEach((d, i) => {
      if (i % step === 0) {
        const x = pad.left + (i / (dataRef.current.length - 1)) * cw;
        const t = new Date(d.label);
        const label = `${t.getHours().toString().padStart(2, '0')}:${t.getMinutes().toString().padStart(2, '0')}`;
        ctx.fillText(label, x, h - pad.bottom + 14);
      }
    });

    // Legend
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'left';
    ctx.fillStyle = '#00e5ff';
    ctx.fillText('Events/sec', pad.left, 12);
    ctx.fillStyle = '#ff0080';
    ctx.fillText('Anomalies/sec', pad.left + 90, 12);
  }, []);

  useEffect(() => {
    const container = canvasRef.current?.parentElement;
    if (!container) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        draw(Math.round(width), Math.max(Math.round(height), 150));
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, [draw]);

  // Initial draw
  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas) {
      const w = canvas.parentElement?.clientWidth || 600;
      draw(w, 180);
    }
  }, [draw, data]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const pts1 = (canvas as any)._points1 as ChartPoint[] | undefined;
    const pts2 = (canvas as any)._points2 as ChartPoint[] | undefined;
    if (!pts1 || !pts2) return;

    let closest: { dist: number; idx: number; label: string; ev: number; anom: number } = { dist: Infinity, idx: -1, label: '', ev: 0, anom: 0 };
    for (let i = 0; i < pts1.length; i++) {
      const dist = Math.abs(pts1[i].x - mx);
      if (dist < closest.dist) {
        closest = { dist, idx: i, label: pts1[i].label, ev: pts1[i].value, anom: pts2[i].value };
      }
    }

    if (closest.dist < 30) {
      setTooltip({
        x: mx,
        y: my,
        text: `${closest.label} — Events: ${closest.ev.toFixed(2)}, Anomalies: ${closest.anom.toFixed(4)}`,
      });
    } else {
      setTooltip(null);
    }
  };

  return (
    <div className="relative">
      <canvas
        ref={canvasRef}
        className="w-full"
        style={{ height: 180 }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setTooltip(null)}
      />
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-cyber-panel/95 border border-cyber-border rounded px-2 py-1 text-xs font-mono text-cyber-text z-10"
          style={{ left: tooltip.x + 12, top: tooltip.y - 28 }}
        >
          {tooltip.text}
        </div>
      )}
    </div>
  );
}

// ── Status indicator ──
function StatusDot({ status }: { status: string }) {
  const ok = ['ok', 'connected', 'active', 'enabled', 'online', 'healthy', 'running'].includes(status.toLowerCase());
  const warn = ['warning', 'degraded', 'questionable'].includes(status.toLowerCase());
  const color = ok ? '#00e676' : warn ? '#ffab00' : '#ff1744';
  return (
    <span className="inline-block w-2.5 h-2.5 rounded-full mr-2" style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}80` }} />
  );
}

// ── Metric Card ──
function MetricCard({ icon, label, value, sub, color = '#00e5ff' }: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="cyber-card p-4 cyber-card-hover">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-8 h-8 rounded-md flex items-center justify-center" style={{ backgroundColor: `${color}18`, border: `1px solid ${color}30` }}>
          <span style={{ color }}>{icon}</span>
        </div>
        <div className="flex-1">
          <div className="text-xs text-cyber-textMuted uppercase tracking-wide">{label}</div>
          <div className="text-xl font-bold font-mono" style={{ color }}>{value}</div>
          {sub && <div className="text-xs text-cyber-textMuted">{sub}</div>}
        </div>
      </div>
    </div>
  );
}

// ── Subsystem Row ──
function SubsystemRow({ name, status, detail }: { name: string; status: string; detail: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-cyber-border/50 last:border-0">
      <div className="flex items-center gap-2">
        <StatusDot status={status} />
        <span className="text-sm font-medium text-cyber-text">{name}</span>
      </div>
      <span className="text-xs text-cyber-textMuted font-mono truncate max-w-[200px]" title={detail}>{detail}</span>
    </div>
  );
}

// ── Format uptime ──
function formatUptime(seconds: number): string {
  if (seconds <= 0) return 'N/A';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ═══════════════════════════════════════════════════
// ObservabilityTab
// ═══════════════════════════════════════════════════
export default function ObservabilityTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<PipelineHealthData>({
    queryKey: ['pipeline-health'],
    queryFn: api.pipelineHealth,
    refetchInterval: 15000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-10 h-10 mx-auto mb-3 rounded-full border-2 border-cyber-border border-t-cyber-accent animate-spin" />
          <div className="text-sm text-cyber-textMuted">Loading observability data...</div>
        </div>
      </div>
    );
  }
  if (isError && error) {
    return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Observability" />;
  }

  const tp = data?.throughput ?? {};
  const err = data?.error_rates ?? {};
  const res = data?.resources ?? {};
  const ts = data?.timescaledb ?? {};
  const rs = data?.redis_stream ?? {};

  // Build chart data from throughput_timeline
  const chartData: ChartPoint[] = (data?.throughput_timeline ?? []).map((pt) => ({
    x: 0,
    y1: pt.events,
    y2: pt.anomalies ?? 0,
    label: pt.timestamp,
  }));

  // Compute gauge-like percentages for resource cards
  const cpuPct = typeof res?.cpu?.usage_pct === 'number' ? res.cpu.usage_pct : 0;
  const memPct = typeof res?.memory?.pct_used === 'number' ? res.memory.pct_used : 0;
  const diskPct = typeof res?.disk?.pct_used === 'number' ? res.disk.pct_used : 0;
  const dbMb = typeof res?.db_size?.mb === 'number' ? res.db_size.mb : 0;
  const redisMb = typeof res?.redis?.used_mb === 'number' ? res.redis.used_mb : 0;

  // Overall health color
  const overallOk = data?.db_connected === true && cpuPct < 90 && memPct < 90;
  const healthColor = overallOk ? '#00e676' : '#ffab00';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 mb-2">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <Activity size={16} className="text-cyber-accent" />
        </div>
        <div>
          <h2 className="text-lg font-bold">Observability</h2>
          <p className="text-xs text-cyber-textMuted">Pipeline health, throughput, errors, and resource monitoring</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <StatusDot status={overallOk ? 'ok' : 'warning'} />
          <span className="text-xs font-mono text-cyber-textMuted">
            Uptime: {formatUptime(tp.uptime_seconds ?? 0)}
          </span>
        </div>
      </div>

      {/* ── Row 1: Throughput metrics ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricCard
          icon={<Gauge size={16} />}
          label="Events/sec"
          value={(tp.events_per_sec ?? 0).toFixed(2)}
          sub={`Total: ${(tp.total_events ?? 0).toLocaleString()}`}
          color="#00e5ff"
        />
        <MetricCard
          icon={<AlertTriangle size={16} />}
          label="Anomalies/sec"
          value={(tp.anomalies_per_sec ?? 0).toFixed(4)}
          sub={`Total: ${(tp.total_anomalies ?? 0).toLocaleString()}`}
          color="#ff0080"
        />
        <MetricCard
          icon={<ShieldCheck size={16} />}
          label="Alerts/sec"
          value={(tp.alerts_per_sec ?? 0).toFixed(4)}
          sub={`Total: ${(tp.total_alerts ?? 0).toLocaleString()}`}
          color="#ffab00"
        />
        <MetricCard
          icon={<Database size={16} />}
          label="Anomaly Rate"
          value={`${(data?.anomaly_rate ?? 0).toFixed(2)}%`}
          sub={data?.db_connected ? 'DB connected' : 'DB disconnected'}
          color={data?.db_connected ? '#00e676' : '#ff1744'}
        />
      </div>

      {/* ── Row 2: Throughput Timeline Chart ── */}
      <div className="cyber-card p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-cyber-text">Throughput (last 60 min)</h3>
          {chartData.length === 0 && <span className="text-xs text-cyber-textMuted">No timeline data yet</span>}
        </div>
        {chartData.length > 1 ? (
          <ThroughputChart data={chartData} />
        ) : (
          <div className="h-[180px] flex items-center justify-center text-cyber-textMuted text-sm">
            Waiting for event data...
          </div>
        )}
      </div>

      {/* ── Row 3: Error Rates ── */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
          <AlertTriangle size={14} className="text-cyber-red" />
          Error Rates (cumulative)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-red">
              {err.total_errors ?? 0}
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Total Errors</div>
          </div>
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-yellow">
              {err.db_errors ?? 0}
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">DB Errors</div>
          </div>
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-purple">
              {err.dns_errors ?? 0}
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">DNS Failures</div>
          </div>
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-blue">
              {err.discord_errors ?? 0}
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Discord Send Failures</div>
          </div>
        </div>
      </div>

      {/* ── Row 4: Resource Usage ── */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
          <Server size={14} className="text-cyber-green" />
          Resource Usage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {/* CPU */}
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono" style={{ color: cpuPct >= 90 ? '#ff1744' : cpuPct >= 70 ? '#ffab00' : '#00e676' }}>
              {cpuPct.toFixed(1)}%
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">CPU</div>
            <div className="w-full h-1.5 bg-cyber-darker rounded-full mt-2 overflow-hidden">
              <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(cpuPct, 100)}%`, backgroundColor: cpuPct >= 90 ? '#ff1744' : cpuPct >= 70 ? '#ffab00' : '#00e676' }} />
            </div>
          </div>
          {/* Memory */}
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono" style={{ color: memPct >= 90 ? '#ff1744' : memPct >= 70 ? '#ffab00' : '#00e676' }}>
              {memPct.toFixed(1)}%
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Memory</div>
            <div className="w-full h-1.5 bg-cyber-darker rounded-full mt-2 overflow-hidden">
              <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(memPct, 100)}%`, backgroundColor: memPct >= 90 ? '#ff1744' : memPct >= 70 ? '#ffab00' : '#00e676' }} />
            </div>
          </div>
          {/* Disk */}
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono" style={{ color: diskPct >= 90 ? '#ff1744' : diskPct >= 70 ? '#ffab00' : '#00e676' }}>
              {diskPct.toFixed(1)}%
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Disk</div>
            <div className="w-full h-1.5 bg-cyber-darker rounded-full mt-2 overflow-hidden">
              <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(diskPct, 100)}%`, backgroundColor: diskPct >= 90 ? '#ff1744' : diskPct >= 70 ? '#ffab00' : '#00e676' }} />
            </div>
          </div>
          {/* DB Size */}
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-accent">
              {dbMb > 1024 ? `${(dbMb / 1024).toFixed(1)} GB` : `${dbMb.toFixed(0)} MB`}
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Database Size</div>
          </div>
          {/* Redis */}
          <div className="text-center p-3 bg-cyber-panel/50 rounded-lg border border-cyber-border">
            <div className="text-2xl font-bold font-mono text-cyber-purple">
              {redisMb.toFixed(1)} MB
            </div>
            <div className="text-xs text-cyber-textMuted mt-1">Redis Memory</div>
          </div>
        </div>
      </div>

      {/* ── Row 5: Infrastructure Status ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* TimescaleDB */}
        <div className="cyber-card p-4">
          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
            <Database size={14} className="text-cyber-accent" />
            TimescaleDB
          </h3>
          <div className="space-y-0">
            <SubsystemRow
              name="Extension"
              status={ts.enabled ? 'active' : 'disabled'}
              detail={ts.enabled ? (ts.version ? `v${ts.version}` : 'enabled') : 'not installed'}
            />
            <SubsystemRow
              name="Hypertable"
              status={ts.hypertable ? 'active' : 'inactive'}
              detail={ts.hypertable ? 'normalized_events' : 'not configured'}
            />
            <SubsystemRow
              name="Chunks"
              status="ok"
              detail={`${ts.chunks ?? 0} chunks`}
            />
          </div>
        </div>

        {/* Redis Streams */}
        <div className="cyber-card p-4">
          <h3 className="text-sm font-semibold text-cyber-text mb-3 flex items-center gap-2">
            <Wifi size={14} className="text-cyber-purple" />
            Redis Streams
          </h3>
          <div className="space-y-0">
            <SubsystemRow
              name="Stream"
              status={rs.enabled ? 'active' : 'disabled'}
              detail={rs.enabled ? `Length: ${rs.stream_length ?? 'N/A'}` : 'not enabled'}
            />
            <SubsystemRow
              name="Consumer Lag"
              status={typeof rs.group_lag === 'number' && rs.group_lag > 100 ? 'warning' : 'ok'}
              detail={rs.group_lag !== undefined ? `${rs.group_lag} messages behind` : 'unknown'}
            />
            <SubsystemRow
              name="Pending Messages"
              status="ok"
              detail={`${rs.pending_messages ?? 0} pending`}
            />
          </div>
        </div>
      </div>

      {/* ── Last event ── */}
      <div className="cyber-card p-3 flex items-center gap-3">
        <Clock size={14} className="text-cyber-textMuted flex-shrink-0" />
        <span className="text-xs text-cyber-textMuted">Last event:</span>
        <span className="text-xs font-mono text-cyber-text">
          {data?.last_event ? new Date(data.last_event).toLocaleString() : 'No events yet'}
        </span>
      </div>
    </div>
  );
}
