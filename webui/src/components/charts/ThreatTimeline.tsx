// ═══════════════════════════════════════════════════
// ThreatTimeline - Canvas 2D IP attack timeline
// Follows CanvasBarChart/CanvasAreaChart patterns.
// Renders chronological timeline events as colored
// dots with source-label rows below.
// Supports action-based coloring + click-to-popup.
// ═══════════════════════════════════════════════════

import { useRef, useEffect, useCallback, useState } from 'react';
import { CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';
import type { TimelineEvent, IpTimelineEvent } from '@/types';

// ── Base source colors ──
const SOURCE_COLORS: Record<string, string> = {
  firewall: '#ff363c',
  nginx: '#ffa500',
  ids: '#ff00ff',
  dns: '#00ffd5',
  zenarmor: '#7c3aed',
  wan_flap: '#ffff64',
  service: '#00ff88',
  baseline: '#8338ec',
};

function sourceColor(source: string): string {
  return SOURCE_COLORS[source] || CYBER.textMuted;
}

// ── Action-based color override ──
function eventColor(source: string, action: string): string {
  const a = action.toLowerCase();
  if (source === 'firewall') {
    if (a.includes('block') || a.includes('drop') || a.includes('reject')) return '#ff1744';
    if (a.includes('pass') || a.includes('allow')) return '#00ff88';
  }
  if (source === 'nginx') {
    if (a.includes('404') || a.includes('4xx') || a.includes('5xx')) return '#ff7800';
    if (a.includes('request') || a.includes('200') || a.includes('301')) return '#00b4d8';
  }
  if (source === 'ids') {
    if (a.includes('signature') || a.includes('alert') || a.includes('trigger')) return '#ff00ff';
  }
  if (source === 'dns') {
    if (a.includes('resolution') || a.includes('query') || a.includes('resolve')) return '#00ffd5';
  }
  if (source === 'zenarmor') {
    if (a.includes('policy') || a.includes('block')) return '#ff006e';
  }
  return sourceColor(source);
}

// ── Check if event has action field (IpTimelineEvent vs TimelineEvent) ──
function hasAction(evt: TimelineEvent | IpTimelineEvent): evt is IpTimelineEvent {
  return 'action' in evt && typeof (evt as IpTimelineEvent).action === 'string';
}

interface ThreatTimelineProps {
  events: (TimelineEvent | IpTimelineEvent)[];
  ip?: string;
  height?: number;
  onEventClick?: (event: TimelineEvent | IpTimelineEvent) => void;
}

export default function ThreatTimeline({ events, ip, height = 280, onEventClick }: ThreatTimelineProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | IpTimelineEvent | null>(null);
  const eventsRef = useRef(events);
  eventsRef.current = events;

  const draw = useCallback((w: number, h: number) => {
    const canvas = canvasRef.current;
    if (!canvas || eventsRef.current.length === 0) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const sorted = [...eventsRef.current].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const minTime = new Date(sorted[0].timestamp).getTime();
    const maxTime = new Date(sorted[sorted.length - 1].timestamp).getTime();
    const range = Math.max(maxTime - minTime, 1);

    const padding = { top: 30, right: 20, bottom: 50, left: 20 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;

    // Time axis labels (top)
    ctx.fillStyle = CYBER.textMuted;
    ctx.font = '10px monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(new Date(minTime).toLocaleTimeString(), padding.left, 4);
    ctx.textAlign = 'right';
    ctx.fillText(new Date(maxTime).toLocaleTimeString(), w - padding.right, 4);

    // IP label
    if (ip) {
      ctx.fillStyle = CYBER.text;
      ctx.font = 'bold 12px monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(ip, padding.left, 18);
    }

    // Collect unique sources for label rows below timeline bar
    const uniqueSources = [...new Set(sorted.map(e => e.source))];

    const rowH = Math.min(14, Math.max(10, chartH / Math.max(uniqueSources.length, 1)));
    const startY = padding.top;

    // Store hit regions for hover + click
    const hitRegions: Array<{ cx: number; cy: number; r: number; event: TimelineEvent | IpTimelineEvent }> = [];

    // Draw each source as a separate row
    uniqueSources.forEach((src, si) => {
      const y = startY + si * rowH;

      // Source label on left
      ctx.fillStyle = sourceColor(src);
      ctx.font = '9px monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText(src, padding.left - 4, y + rowH / 2);

      // Draw a faint horizontal line
      ctx.strokeStyle = `${sourceColor(src)}20`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padding.left, y + rowH / 2);
      ctx.lineTo(w - padding.right, y + rowH / 2);
      ctx.stroke();

      // Draw dots for this source's events
      const sourceEvents = sorted.filter(e => e.source === src);
      sourceEvents.forEach(evt => {
        const pct = (new Date(evt.timestamp).getTime() - minTime) / range;
        const cx = padding.left + pct * chartW;
        const cy = y + rowH / 2;
        const action = hasAction(evt) ? evt.action : '';
        const dotColor = hasAction(evt) ? eventColor(src, action) : sourceColor(src);

        // Glow
        ctx.beginPath();
        ctx.arc(cx, cy, 5, 0, Math.PI * 2);
        ctx.fillStyle = `${dotColor}30`;
        ctx.fill();

        // Dot
        ctx.beginPath();
        ctx.arc(cx, cy, 3, 0, Math.PI * 2);
        ctx.fillStyle = dotColor;
        ctx.fill();
        ctx.strokeStyle = `${dotColor}80`;
        ctx.lineWidth = 1;
        ctx.stroke();

        hitRegions.push({ cx, cy, r: 6, event: evt });
      });
    });

    // Store hit regions on data ref for hover detection
    (eventsRef.current as any)._hitRegions = hitRegions;
  }, [ip]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        draw(entry.contentRect.width, height);
      }
    });
    ro.observe(container);
    draw(container.offsetWidth, height);
    return () => ro.disconnect();
  }, [draw, height]);

  const getHitEvent = (mx: number, my: number): { event: TimelineEvent | IpTimelineEvent } | null => {
    const hitRegions = (eventsRef.current as any)._hitRegions as Array<{ cx: number; cy: number; r: number; event: TimelineEvent | IpTimelineEvent }> | undefined;
    if (!hitRegions) return null;

    let closest: typeof hitRegions[0] | null = null;
    let minDist = Infinity;
    for (const hr of hitRegions) {
      const dist = Math.sqrt((mx - hr.cx) ** 2 + (my - hr.cy) ** 2);
      if (dist < hr.r && dist < minDist) {
        minDist = dist;
        closest = hr;
      }
    }
    return closest ? { event: closest.event } : null;
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const hit = getHitEvent(mx, my);
    if (hit) {
      const evt = hit.event;
      const ts = new Date(evt.timestamp).toLocaleTimeString();
      const action = hasAction(evt) ? ` | ${evt.action}` : '';
      setTooltip({
        x: mx,
        y: my - 10,
        text: `[${evt.source}]${action} ${evt.signal_type} — ${ts}\n${evt.description}`,
      });
    } else {
      setTooltip(null);
    }
  };

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const hit = getHitEvent(mx, my);
    if (hit) {
      setSelectedEvent(prev => prev === hit.event ? null : hit.event);
      onEventClick?.(hit.event);
    } else {
      setSelectedEvent(null);
    }
  };

  if (!events || events.length === 0) {
    return <div className="h-[280px] flex items-center justify-center text-xs text-cyber-textMuted">No timeline data</div>;
  }

  return (
    <div ref={containerRef} className="relative w-full" style={{ height }}>
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        style={{ display: 'block', cursor: 'pointer' }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => { setTooltip(null); }}
        onClick={handleClick}
      />
      {tooltip && (
        <div
          className="absolute z-50 pointer-events-none px-2 py-1 rounded text-xs font-mono whitespace-pre-wrap"
          style={{
            left: Math.min(tooltip.x + 10, (containerRef.current?.offsetWidth ?? 200) - 200),
            top: tooltip.y - 10,
            ...RECHARTS_TOOLTIP,
          }}
        >
          {tooltip.text}
        </div>
      )}

      {/* Event detail popup */}
      {selectedEvent && (
        <div
          className="absolute z-50 right-4 top-12 w-72 rounded-lg border border-cyber-border/60 shadow-xl backdrop-blur-sm"
          style={{ ...RECHARTS_TOOLTIP }}
        >
          <div className="p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-cyber-accent uppercase">
                {selectedEvent.source}
              </span>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-xs text-cyber-textMuted hover:text-cyber-text cursor-pointer"
              >
                ✕
              </button>
            </div>
            <div className="text-xs font-mono text-cyber-text">
              {new Date(selectedEvent.timestamp).toLocaleString()}
            </div>
            <div className="text-sm text-cyber-text leading-relaxed">
              {selectedEvent.description || selectedEvent.signal_type}
            </div>
            {hasAction(selectedEvent) && (
              <>
                <div className="flex justify-between text-xs">
                  <span className="text-cyber-textMuted">Action</span>
                  <span className="font-mono" style={{ color: eventColor(selectedEvent.source, selectedEvent.action) }}>
                    {selectedEvent.action}
                  </span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-cyber-textMuted">Source</span>
                  <span className="font-mono text-cyber-text">{selectedEvent.src_ip || '-'}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-cyber-textMuted">Dest</span>
                  <span className="font-mono text-cyber-text">{selectedEvent.dst_ip || '-'}</span>
                </div>
                {selectedEvent.dst_port != null && selectedEvent.dst_port !== null && (
                  <div className="flex justify-between text-xs">
                    <span className="text-cyber-textMuted">Ports</span>
                    <span className="font-mono text-cyber-text">
                      {selectedEvent.src_port ?? '*'}:{selectedEvent.dst_port}
                    </span>
                  </div>
                )}
                {selectedEvent.protocol && (
                  <div className="flex justify-between text-xs">
                    <span className="text-cyber-textMuted">Protocol</span>
                    <span className="font-mono text-cyber-text">{selectedEvent.protocol}</span>
                  </div>
                )}
                {selectedEvent.rule_name && (
                  <div className="flex justify-between text-xs">
                    <span className="text-cyber-textMuted">Rule</span>
                    <span className="font-mono text-cyber-accent/80 truncate ml-2" title={selectedEvent.rule_name}>
                      {selectedEvent.rule_name}
                    </span>
                  </div>
                )}
              </>
            )}
            <div className="flex justify-between text-xs">
              <span className="text-cyber-textMuted">Severity</span>
              <span className="font-mono font-bold" style={{
                color: selectedEvent.severity === 'critical' ? CYBER.red
                  : selectedEvent.severity === 'high' ? CYBER.orange
                  : selectedEvent.severity === 'medium' ? CYBER.yellow
                  : CYBER.green,
              }}>
                {selectedEvent.severity.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
