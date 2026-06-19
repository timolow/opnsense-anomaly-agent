// ═══════════════════════════════════════════════════
// Heatmap Tab - IP × Hour activity heatmap
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { HeatmapData } from '@/types';
import { Map } from 'lucide-react';

export default function HeatmapTab() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; val: number; row: string; col: string } | null>(null);
  
  const { data } = useQuery<HeatmapData>({
    queryKey: ['heatmap'],
    queryFn: api.heatmap,
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (!data || !canvasRef.current) return;
    
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { matrix, labels, rowLabels } = data;
    const cellW = canvas.width / (matrix[0]?.length || 1);
    const cellH = canvas.height / (matrix.length || 1);

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw cells
    matrix.forEach((row, i) => {
      row.forEach((val, j) => {
        const intensity = Math.min(val / 100, 1);
        // Cyberpunk cyan-to-purple gradient based on intensity
        const r = Math.round(0 + intensity * 255);
        const g = Math.round(229 * (1 - intensity) + 0 * intensity);
        const b = Math.round(255);
        const alpha = 0.3 + intensity * 0.7;
        
        ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${alpha})`;
        ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);

        // Glow effect for high intensity
        if (intensity > 0.7) {
          ctx.shadowColor = `rgba(${r}, ${g}, ${b}, 0.8)`;
          ctx.shadowBlur = 8;
          ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
          ctx.shadowBlur = 0;
        }
      });
    });

    // Row labels
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    rowLabels.forEach((label, i) => {
      ctx.fillText(label, 4, i * cellH + cellH / 2 + 3);
    });

    // Column labels
    labels.forEach((label, j) => {
      ctx.fillText(label, j * cellW + 4, canvas.height - 4);
    });
  }, [data]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!data || !canvasRef.current) return;
    
    const rect = canvasRef.current.getBoundingClientRect();
    const { matrix, labels, rowLabels } = data;
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const cellW = rect.width / (matrix[0]?.length || 1);
    const cellH = rect.height / (matrix.length || 1);
    
    const col = Math.floor(x / cellW);
    const row = Math.floor(y / cellH);
    
    if (row >= 0 && row < matrix.length && col >= 0 && col < matrix[0].length) {
      setTooltip({
        x: e.clientX,
        y: e.clientY,
        val: matrix[row][col],
        row: rowLabels[row] || '',
        col: labels[col] || '',
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <HeatMap size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Traffic Heatmap</h2>
        <span className="text-xs text-cyber-textMuted font-mono">IP × Hour Activity</span>
      </div>

      <div className="cyber-card p-4 scanlines relative">
        <canvas
          ref={canvasRef}
          width={1200}
          height={500}
          className="w-full h-auto rounded cursor-crosshair"
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(null)}
        />

        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed pointer-events-none z-50 cyber-card px-3 py-2"
            style={{
              left: tooltip.x + 10,
              top: tooltip.y - 40,
              minWidth: 120,
            }}
          >
            <div className="text-xs font-mono text-cyber-textMuted">{tooltip.row} @ {tooltip.col}:00</div>
            <div className="text-lg font-bold font-mono text-cyber-accent" style={{ textShadow: '0 0 10px rgba(0,229,255,0.5)' }}>
              {tooltip.val.toLocaleString()} events
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex items-center gap-4 mt-4 pt-3 border-t border-cyber-border">
          <span className="text-xs text-cyber-textMuted">Low</span>
          <div className="flex gap-0.5">
            {[0, 0.25, 0.5, 0.75, 1].map((v, i) => (
              <div key={i} className="w-4 h-4 rounded-sm" style={{
                backgroundColor: `rgba(${Math.round(v * 255)}, ${Math.round(229 * (1 - v))}, 255, 0.8)`,
              }} />
            ))}
          </div>
          <span className="text-xs text-cyber-textMuted">High</span>
        </div>
      </div>
    </div>
  );
}
