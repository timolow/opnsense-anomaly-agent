import { useRef, useEffect, useCallback, useState } from 'react';
import { CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';

interface PieSlice {
  name: string;
  value: number;
  color: string;
}

interface CanvasPieChartProps {
  data: PieSlice[];
  height?: number;
  outerRadius?: number;
  innerRadius?: number;
}

export default function CanvasPieChart({ data, height = 250, outerRadius = 80, innerRadius = 50 }: CanvasPieChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; name: string; value: number; color: string } | null>(null);
  const dataRef = useRef(data);
  dataRef.current = data;

  // Pre-compute slice angles
  const slices = useCallback(() => {
    const total = dataRef.current.reduce((s, d) => s + d.value, 0) || 1;
    let start = -Math.PI / 2;
    return dataRef.current.map((d) => {
      const angle = (d.value / total) * Math.PI * 2;
      const slice = { ...d, start, end: start + angle, mid: start + angle / 2 };
      start += angle;
      return slice;
    });
  }, []);

  const draw = useCallback((w: number, h: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2;
    const cy = h / 2;
    const outer = Math.min(outerRadius, Math.min(w, h) / 2 - 20);
    const inner = Math.min(innerRadius, outer * 0.6);

    const allSlices = slices();
    (dataRef.current as any)._slices = allSlices;
    (dataRef.current as any)._center = { cx, cy, outer, inner };

    allSlices.forEach((s) => {
      if (s.value === 0) return;
      ctx.beginPath();
      ctx.arc(cx, cy, outer, s.start, s.end);
      ctx.arc(cx, cy, inner, s.end, s.start, true);
      ctx.closePath();
      ctx.fillStyle = s.color;
      ctx.shadowColor = s.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      // Border
      ctx.strokeStyle = '#0d1117';
      ctx.lineWidth = 2;
      ctx.stroke();
    });
  }, [slices, outerRadius, innerRadius]);

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
    const center = (dataRef.current as any)._center as { cx: number; cy: number; outer: number; inner: number } | undefined;
    const allSlices = (dataRef.current as any)._slices as Array<typeof dataRef.current[0] & { start: number; end: number }> | undefined;

    if (!center || !allSlices) {
      setTooltip(null);
      return;
    }

    const dx = mx - center.cx;
    const dy = my - center.cy;
    const dist = Math.sqrt(dx * dx + dy * dy);

    if (dist < center.inner || dist > center.outer) {
      setTooltip(null);
      return;
    }

    let angle = Math.atan2(dy, dx);
    if (angle < -Math.PI / 2) angle += Math.PI * 2;

    for (const s of allSlices) {
      if (angle >= s.start && angle < s.end && s.value > 0) {
        setTooltip({ x: mx, y: my, name: s.name, value: s.value, color: s.color });
        return;
      }
    }
    setTooltip(null);
  };

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
          className="absolute z-50 pointer-events-none px-2 py-1 rounded text-xs font-mono whitespace-nowrap"
          style={{
            left: Math.min(tooltip.x + 10, (containerRef.current?.offsetWidth ?? 200) - 100),
            top: tooltip.y - 36,
            ...RECHARTS_TOOLTIP,
          }}
        >
          <div style={{ color: tooltip.color }}>{tooltip.name}</div>
          <div className="font-bold" style={{ color: CYBER.accent }}>{tooltip.value.toLocaleString()}</div>
        </div>
      )}
    </div>
  );
}
