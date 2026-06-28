import { useRef, useEffect, useCallback, useState } from 'react';
import { CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';

interface AreaData {
  x: number;
  value: number;
}

interface CanvasAreaChartProps {
  data: AreaData[];
  height?: number;
  color?: string;
}

export default function CanvasAreaChart({ data, height = 64, color = '#00ffd5' }: CanvasAreaChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
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

    const padding = 2;
    const chartW = w - padding * 2;
    const chartH = h - padding * 2;

    const values = dataRef.current.map((d) => d.value);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;

    const points = dataRef.current.map((d, i) => ({
      x: padding + (i / (dataRef.current.length - 1)) * chartW,
      y: padding + chartH - ((d.value - min) / range) * chartH,
      value: d.value,
    }));

    // Area fill with gradient
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + '59');
    grad.addColorStop(1, color + '03');
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.lineTo(points[points.length - 1].x, h - padding);
    ctx.lineTo(points[0].x, h - padding);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.strokeStyle = color + 'e6';
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();

    // Hover indicator
    if (hoverIdx !== null && points[hoverIdx]) {
      const p = points[hoverIdx];
      ctx.beginPath();
      ctx.setLineDash([2, 2]);
      ctx.moveTo(p.x, 2);
      ctx.lineTo(p.x, h - 2);
      ctx.strokeStyle = color + '66';
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = '#0d1117';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      (dataRef.current as any)._points = points;
    }
  }, [hoverIdx, color]);

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
  }, [draw, height, hoverIdx]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const pts = (dataRef.current as any)._points as Array<{ x: number }> | undefined;
    if (!pts || pts.length < 2) {
      setHoverIdx(null);
      return;
    }
    let closest = 0;
    let minDist = Infinity;
    pts.forEach((p: { x: number }, i: number) => {
      const dist = Math.abs(p.x - mx);
      if (dist < minDist) {
        minDist = dist;
        closest = i;
      }
    });
    setHoverIdx(closest);
  };

  if (data.length < 2) {
    return <div className="h-[64px] flex items-center justify-center text-xs text-cyber-textMuted">No timeline data</div>;
  }

  return (
    <div ref={containerRef} className="relative w-full" style={{ height }}>
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        style={{ display: 'block' }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setHoverIdx(null)}
      />
    </div>
  );
}
