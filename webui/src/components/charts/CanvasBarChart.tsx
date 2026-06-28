import { useRef, useEffect, useCallback, useState } from 'react';
import { CYBER, RECHARTS_TOOLTIP } from '@/utils/colors';

interface BarData {
  name: string;
  value: number;
  color: string;
}

interface CanvasBarChartProps {
  data: BarData[];
  height?: number;
  barSize?: number;
}

export default function CanvasBarChart({ data, height = 200, barSize = 24 }: CanvasBarChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; name: string; value: number } | null>(null);
  const dataRef = useRef(data);
  dataRef.current = data;

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

    const padding = { top: 10, right: 30, bottom: 30, left: 0 };
    const chartW = w - padding.left - padding.right;
    const chartH = h - padding.top - padding.bottom;

    const maxVal = Math.max(...dataRef.current.map((d) => d.value), 1);
    const barCount = dataRef.current.length;
    const gap = 8;
    const totalGap = gap * (barCount - 1);
    const actualBarW = Math.min((chartW - totalGap) / barCount, 60);
    const actualBarSize = Math.min(barSize, chartH);

    dataRef.current.forEach((d, i) => {
      const x = padding.left + i * (actualBarW + gap) + (chartW - barCount * actualBarW - totalGap) / 2;
      const barH = (d.value / maxVal) * actualBarSize;
      const y = padding.top + chartH - barH;

      // Bar with rounded top-right and bottom-right corners
      const r = Math.min(4, actualBarW / 2);
      ctx.beginPath();
      ctx.moveTo(x, y + chartH - actualBarSize);
      ctx.lineTo(x, y + r);
      ctx.quadraticCurveTo(x, y, x + r, y);
      ctx.lineTo(x + actualBarW - r, y);
      ctx.quadraticCurveTo(x + actualBarW, y, x + actualBarW, y + r);
      ctx.lineTo(x + actualBarW, y + chartH - actualBarSize);
      ctx.closePath();
      ctx.fillStyle = d.color;
      ctx.fill();

      // Store bar bounds for hover detection
      (d as any)._barX = x;
      (d as any)._barY = y;
      (d as any)._barW = actualBarW;
      (d as any)._barH = barH;

      // X-axis label
      ctx.fillStyle = CYBER.textMuted;
      ctx.font = '11px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(d.name, x + actualBarW / 2, padding.top + chartH + 4);
    });
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width } = entry.contentRect;
        draw(width, height);
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

    let found: typeof tooltip = null;
    for (const d of dataRef.current) {
      const bx = (d as any)._barX ?? 0;
      const by = (d as any)._barY ?? 0;
      const bw = (d as any)._barW ?? 0;
      const bh = (d as any)._barH ?? 0;
      if (mx >= bx && mx <= bx + bw && my >= by && my <= by + bh + 20) {
        found = { x: mx, y: my, name: d.name, value: d.value };
        break;
      }
    }
    setTooltip(found);
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
          <div style={{ color: CYBER.text }}>{tooltip.name}</div>
          <div className="font-bold" style={{ color: CYBER.accent }}>{tooltip.value.toLocaleString()}</div>
        </div>
      )}
    </div>
  );
}
