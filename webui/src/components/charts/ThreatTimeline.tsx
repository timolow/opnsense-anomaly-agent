// ═══════════════════════════════════════════════════
// ThreatTimeline - Canvas 2D IP attack timeline
// Follows CanvasBarChart/CanvasAreaChart patterns.
// Renders chronological timeline events as colored
// dots with source-label rows below.
// ═══════════════════════════════════════════════════

import { useRef, useEffect, useCallback, useState } from 'react';
import { CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';
import type { TimelineEvent } from '@/types';

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

interface ThreatTimelineProps {
  events: TimelineEvent[];
  ip?: string;
  height?: number;
}

export default function ThreatTimeline({ events, ip, height = 280 }: ThreatTimelineProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; text: string } | null>(null);
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
      ctx.fillText(ip, padding.left, 4);
    }

    // Collect unique sources for label rows below timeline bar
    const uniqueSources = [...new Set(sorted.map(e => e.source))];

    const rowH = Math.min(14, Math.max(10, chartH / Math.max(uniqueSources.length, 1)));
    const startY = padding.top;

    // Store hit regions for hover
    const hitRegions: Array<{ cx: number; cy: number; r: number; event: TimelineEvent }> = [];

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
        const dotColor = sourceColor(src);

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

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    const hitRegions = (eventsRef.current as any)._hitRegions as Array<{ cx: number; cy: number; r: number; event: TimelineEvent }> | undefined;
    if (!hitRegions) {
      setTooltip(null);
      return;
    }

    let closest: typeof hitRegions[0] | null = null;
    let minDist = Infinity;
    for (const hr of hitRegions) {
      const dist = Math.sqrt((mx - hr.cx) ** 2 + (my - hr.cy) ** 2);
      if (dist < hr.r && dist < minDist) {
        minDist = dist;
        closest = hr;
      }
    }

    if (closest) {
      const evt = closest.event;
      const ts = new Date(evt.timestamp).toLocaleTimeString();
      setTooltip({
        x: closest.cx,
        y: closest.cy - 10,
        text: `[${evt.source}] ${evt.signal_type} — ${ts}\n${evt.description}`,
      });
    } else {
      setTooltip(null);
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
        style={{ display: 'block' }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setTooltip(null)}
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
    </div>
  );
}
