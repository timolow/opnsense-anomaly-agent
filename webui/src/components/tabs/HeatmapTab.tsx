// Heatmap Tab - IP x Hour activity heatmap
import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { HeatmapData } from '@/types';
import { Flame } from 'lucide-react';

export default function HeatmapTab() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; val: number; ip: string; hour: string } | null>(null);
  
  const { data, isLoading } = useQuery<HeatmapData>({
    queryKey: ['heatmap'],
    queryFn: () => api.heatmap(),
    refetchInterval: 60000,
  });

  useEffect(() => {
    if (!data || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { matrix, labels, rowLabels } = data;
    const numCols = labels.length;
    const numRows = rowLabels.length;
    
    if (numCols === 0 || numRows === 0) return;

    // Responsive canvas sizing based on container width
    const containerWidth = canvas.parentElement ? canvas.parentElement.clientWidth - 32 : 800; // minus padding
    const cellW_target = 60; // target cell width
    const canvasWidth = Math.max(containerWidth, numCols * cellW_target);
    const cellH = Math.max(20, Math.min(30, 600 / numRows));
    const canvasHeight = Math.max(200, numRows * cellH);
    
    canvas.width = canvasWidth;
    canvas.height = canvasHeight;
    const cellW = canvasWidth / numCols;

    // Find max value
    let maxVal = 0;
    for (const row of matrix) {
      for (const v of row) {
        if (v > maxVal) maxVal = v;
      }
    }

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw cells
    for (let i = 0; i < matrix.length; i++) {
      for (let j = 0; j < matrix[i].length; j++) {
        const val = matrix[i][j];
        const intensity = maxVal > 0 ? val / maxVal : 0;
        const r = Math.round(intensity * 255);
        const g = Math.round(255 * (1 - intensity));
        const b = 255;
        const alpha = 0.2 + intensity * 0.8;
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
        ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
        if (intensity > 0.8) {
          ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.6)`;
          ctx.shadowBlur = 4;
          ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
          ctx.shadowBlur = 0;
        }
      }
    }

    // Draw labels
    ctx.fillStyle = '#64748b';
    ctx.font = '9px monospace';
    ctx.textAlign = 'right';
    for (let i = 0; i < rowLabels.length; i++) {
      const short = rowLabels[i].length > 18 ? rowLabels[i].substring(0, 15) + '...' : rowLabels[i];
      ctx.fillText(short, cellW - 4, i * cellH + cellH / 2 + 3);
    }

    ctx.textAlign = 'center';
    for (let j = 0; j < labels.length; j++) {
      ctx.fillText(labels[j], j * cellW + cellW / 2, canvas.height - 2);
    }
  }, [data]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!data || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const { matrix, labels, rowLabels } = data;
    const numCols = labels.length;
    const numRows = rowLabels.length;
    const cellW = rect.width / numCols;
    const cellH = rect.height / numRows;
    const col = Math.floor((e.clientX - rect.left) / cellW);
    const row = Math.floor((e.clientY - rect.top) / cellH);
    if (row >= 0 && row < numRows && col >= 0 && col < numCols) {
      setTooltip({
        x: e.clientX,
        y: e.clientY,
        val: matrix[row][col],
        ip: rowLabels[row],
        hour: labels[col],
      });
    } else {
      setTooltip(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
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
        <canvas
          ref={canvasRef}
          className="w-full h-auto rounded cursor-crosshair"
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(null)}
        />

        {tooltip && (
          <div
            className="fixed pointer-events-none z-50 cyber-card px-3 py-2 text-xs font-mono"
            style={{ left: tooltip.x + 10, top: tooltip.y - 40, minWidth: 150 }}
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