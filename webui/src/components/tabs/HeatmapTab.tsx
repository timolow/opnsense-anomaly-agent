// Heatmap Tab - IP x Hour activity heatmap
// Uses SVG-based grid rendering with Recharts ResponsiveContainer
import { useState, useMemo, useCallback } from 'react';
import { ResponsiveContainer } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { HeatmapData } from '@/types';
import { Flame } from 'lucide-react';
import { QueryErrorState } from '../TabErrorBoundary';

export default function HeatmapTab() {
  const [tooltip, setTooltip] = useState<{ col: number; row: number; val: number; ip: string; hour: string } | null>(null);

  const { data, isLoading, error, isError, refetch } = useQuery<HeatmapData>({
    queryKey: ['heatmap'],
    queryFn: () => api.heatmap(),
    refetchInterval: 60000,
  });

  if (isError) return <QueryErrorState error={error} isError={isError} onRetry={refetch} tabName="Traffic Heatmap" />;

  const { maxVal } = useMemo(() => {
    if (!data) return { maxVal: 0 };
    let maxVal = 0;
    for (const row of data.matrix) {
      for (const v of row) {
        if (v > maxVal) maxVal = v;
      }
    }
    return { maxVal };
  }, [data]);

  const handleCellEnter = useCallback((e: React.MouseEvent<SVGRectElement>, col: number, row: number) => {
    if (!data) return;
    setTooltip({
      col,
      row,
      val: data.matrix[row]?.[col] ?? 0,
      ip: data.rowLabels[row] ?? '',
      hour: data.labels[col] ?? '',
    });
  }, [data]);

  const intensityToColor = (intensity: number) => {
    const r = Math.round(intensity * 255);
    const g = Math.round(255 * (1 - intensity));
    const b = 255;
    const alpha = 0.2 + intensity * 0.8;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  };

  if (isLoading || !data) {
    return <TabSkeleton tab="heatmap" />;
  }

  const { matrix, labels, rowLabels } = data;
  const numCols = labels.length;
  const numRows = rowLabels.length;

  if (numCols === 0 || numRows === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-cyber-textMuted">No heatmap data available</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <Flame size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Traffic Heatmap</h2>
        <span className="text-xs text-cyber-textMuted font-mono">IP x Hour Activity</span>
      </div>

      <div className="cyber-card p-4 scanlines relative">
        <div className="text-xs text-cyber-textMuted mb-2 font-mono">
          {numRows} IPs &middot; {numCols} hours &middot; peak {maxVal.toLocaleString()} events
        </div>

        <div style={{ width: '100%', height: '400px' }}>
          <ResponsiveContainer width="100%" height="100%">
            {({ width, height }: { width: number; height: number }) => {
              const cellW = width / numCols;
              const cellH = height / numRows;
              return (
                <svg
                  width={width}
                  height={height}
                  className="cursor-crosshair"
                  onMouseLeave={() => setTooltip(null)}
                >
                  {/* Glow filter */}
                  <defs>
                    <filter id="heatmap-glow">
                      <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                      <feMerge>
                        <feMergeNode in="coloredBlur" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                  </defs>
                  {/* Heatmap cells */}
                  {matrix.map((row, i) =>
                    row.map((val, j) => {
                      const intensity = maxVal > 0 ? val / maxVal : 0;
                      const fill = intensityToColor(intensity);
                      const hasGlow = intensity > 0.8;
                      return (
                        <g key={`cell-${i}-${j}`}>
                          {hasGlow && (
                            <rect
                              x={j * cellW}
                              y={i * cellH}
                              width={cellW - 1}
                              height={cellH - 1}
                              fill={fill}
                              opacity={0.4}
                              filter="url(#heatmap-glow)"
                            />
                          )}
                          <rect
                            x={j * cellW}
                            y={i * cellH}
                            width={cellW - 1}
                            height={cellH - 1}
                            fill={fill}
                            onMouseEnter={(e) => handleCellEnter(e, j, i)}
                          />
                        </g>
                      );
                    })
                  )}
                  {/* Row labels (IPs) */}
                  {rowLabels.map((label, i) => {
                    const short = label.length > 15 ? label.slice(0, 13) + '...' : label;
                    return (
                      <text
                        key={`row-${i}`}
                        x={width - 4}
                        y={i * cellH + cellH / 2 + 3}
                        fill="#64748b"
                        fontSize="9"
                        textAnchor="end"
                        dominantBaseline="middle"
                        fontFamily="monospace"
                      >
                        {short}
                      </text>
                    );
                  })}
                  {/* Column labels (hours) */}
                  {labels.map((label, j) => (
                    <text
                      key={`col-${j}`}
                      x={j * cellW + cellW / 2}
                      y={height - 2}
                      fill="#64748b"
                      fontSize="9"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontFamily="monospace"
                    >
                      {label}
                    </text>
                  ))}
                </svg>
              );
            }}
          </ResponsiveContainer>
        </div>

        {/* Tooltip */}
        {tooltip && (
          <div
            className="cyber-card p-3 text-xs font-mono absolute z-50 pointer-events-none"
            style={{
              right: 16,
              bottom: 16,
              minWidth: 160,
            }}
          >
            <div className="font-semibold">{tooltip.ip}</div>
            <div className="text-cyber-textMuted">{tooltip.hour}</div>
            <div className="text-cyber-accent">{tooltip.val.toLocaleString()} events</div>
          </div>
        )}
      </div>

      <div className="flex items-center gap-4 text-xs text-cyber-textMuted">
        <span>Low</span>
        <div className="flex-1 h-2 rounded" style={{
          background: 'linear-gradient(to right, rgba(0,255,255,0.2), rgba(255,0,255,0.9))'
        }} />
        <span>High</span>
      </div>
    </div>
  );
}