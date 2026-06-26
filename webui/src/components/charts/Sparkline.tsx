// Sparkline - Mini area chart with hover tooltips
// Pure SVG, no Recharts dependency - keeps metric cards lightweight

import { useMemo, useState } from 'react';
import type { SparklinePoint } from '@/types';

interface SparklineProps {
  data: SparklinePoint[];
  color: string;
  height?: number;
  width?: number | string;
}

export default function Sparkline({ data, color, height = 32, width = 120 }: SparklineProps) {
  const [hovered, setHovered] = useState<number | null>(null);

  // Resolve numeric width for SVG calculations (string widths like "100%" need a fallback)
  const numericWidth = typeof width === 'number' ? width : 120;

  const path = useMemo(() => {
    if (data.length < 2) return { area: '', line: '', points: [] as { x: number; y: number; value: number; time: string }[] };

    const values = data.map((d) => d.count);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;
    const padding = 2;
    const chartW = numericWidth - padding * 2;
    const chartH = height - padding * 2;

    const points = data.map((d, i) => {
      const x = padding + (i / (data.length - 1)) * chartW;
      const y = padding + chartH - ((d.count - min) / range) * chartH;
      return { x, y, value: d.count, time: d.time };
    });

    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');

    const areaPath = `${linePath} L${points[points.length - 1].x.toFixed(1)},${(height - padding).toFixed(1)} L${points[0].x.toFixed(1)},${(height - padding).toFixed(1)} Z`;

    return { area: areaPath, line: linePath, points };
  }, [data, color, height, numericWidth]);

  // Empty state
  if (data.length < 2) {
    return (
      <div
        className="relative mt-1"
        style={{ width, height }}
        onMouseLeave={() => setHovered(null)}
      >
        <svg width={width} height={height} className="overflow-visible">
          <rect x="0" y={height / 2 - 1} width={width} height={2} fill={color} opacity={0.2} rx={1} />
        </svg>
      </div>
    );
  }

  const formatValue = (v: number) => {
    if (v >= 1_000_000) return (v / 1_000_000).toFixed(1) + 'M';
    if (v >= 1_000) return (v / 1_000).toFixed(1) + 'K';
    return v.toString();
  };

  const formatTime = (iso: string) => {
    try {
      const d = new Date(iso.replace(' ', 'T'));
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return iso.slice(11, 16);
    }
  };

  return (
    <div
      className="relative mt-1 group/spark"
      style={{ width, height }}
      onMouseLeave={() => setHovered(null)}
    >
      <svg
        width={width}
        height={height}
        className="overflow-visible"
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const mouseX = e.clientX - rect.left;
          let closest = 0;
          let minDist = Infinity;
          path.points.forEach((p, i) => {
            const dist = Math.abs(p.x - mouseX);
            if (dist < minDist) {
              minDist = dist;
              closest = i;
            }
          });
          setHovered(closest);
        }}
      >
        {/* Area fill with gradient */}
        <defs>
          <linearGradient id={`spark-grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.3} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <path d={path.area} fill={`url(#spark-grad-${color.replace('#', '')})`} />
        {/* Line */}
        <path
          d={path.line}
          fill="none"
          stroke={color}
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity={0.9}
        />
        {/* Hover indicator */}
        {hovered !== null && path.points[hovered] && (
          <>
            <line
              x1={path.points[hovered].x}
              y1={2}
              x2={path.points[hovered].x}
              y2={height - 2}
              stroke={color}
              strokeWidth={1}
              strokeDasharray="2 2"
              opacity={0.4}
            />
            <circle
              cx={path.points[hovered].x}
              cy={path.points[hovered].y}
              r={3}
              fill={color}
              stroke="#0d1117"
              strokeWidth={1.5}
            />
          </>
        )}
      </svg>
      {/* Tooltip */}
      {hovered !== null && path.points[hovered] && (
        <div
          className="absolute z-50 pointer-events-none"
          style={{
            left: Math.min(path.points[hovered].x + 6, numericWidth - 80),
            top: -28,
          }}
        >
          <div
            className="px-2 py-1 rounded text-xs font-mono whitespace-nowrap"
            style={{
              background: '#0d1117ee',
              border: `1px solid ${color}44`,
              color: '#e2e8f0',
              boxShadow: `0 0 8px ${color}22`,
            }}
          >
            <span style={{ color }}>{formatValue(path.points[hovered].value)}</span>
            <span className="text-cyber-textMuted ml-1">{formatTime(path.points[hovered].time)}</span>
          </div>
        </div>
      )}
    </div>
  );
}