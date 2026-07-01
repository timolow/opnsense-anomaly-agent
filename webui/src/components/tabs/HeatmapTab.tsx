// Heatmap Tab - IP x Hour activity heatmap
import { useEffect, useRef, useState, useMemo } from 'react';
import { format_ip } from '@/utils/formatIp';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { HeatmapData } from '@/types';
import { Flame, ChevronDown, Filter } from 'lucide-react';
import { CYBER } from '@/utils/colors';

import { HeatmapSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

// Produce the same RGBA the canvas uses for a given [0,1] intensity
function heatmapColor(intensity: number) {
  const r = Math.round(intensity * 255);
  const g = Math.round(255 * (1 - intensity));
  const b = 255;
  const a = 0.2 + intensity * 0.8;
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

const TOP_N_OPTIONS = [10, 25, 50];

const BEHAVIOR_COLORS = {
  all: CYBER.accent,
  benign: '#22c55e',
  suspicious: '#f59e0b',
  hostile: '#ef4444',
};

export default function HeatmapTab() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const legendCanvasRef = useRef<HTMLCanvasElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; val: number; ip: string; hour: string; hostname?: string | null; behavior?: string } | null>(null);
  const [topN, setTopN] = useState<number>(50);
  const [behaviorFilter, setBehaviorFilter] = useState<string>('all');

  // Fetch behavioral profiles for IP classification
  const { data: behaviorProfiles } = useQuery({
    queryKey: ['behavior-profiles'],
    queryFn: async () => {
      try {
        const res = await api.behaviorProfiles();
        return res;
      } catch {
        return [];
      }
    },
    staleTime: 60_000,
    refetchInterval: 120_000,
  });

  // Build IP -> behavior_level map
  const ipBehaviorMap = useMemo(() => {
    const map = new Map<string, string>();
    if (behaviorProfiles) {
      for (const p of behaviorProfiles) {
        map.set(p.ip, p.threat_level || 'benign');
      }
    }
    return map;
  }, [behaviorProfiles]);
  
  const { data, isLoading, isError, error, refetch } = useQuery<HeatmapData>({
    queryKey: ['heatmap'],
    queryFn: () => api.heatmap(),
    refetchInterval: 60000,
  });

  // Client-side top-N filtering + behavior filter
  const filteredData = useMemo(() => {
    if (!data) return null;
    let rows = data.rowLabels.length;
    const matrix = data.matrix;

    // If behavior filter is active, collect IPs matching the filter
    if (behaviorFilter !== 'all' && ipBehaviorMap.size > 0) {
      const filteredIndices: number[] = [];
      for (let i = 0; i < rows; i++) {
        const level = ipBehaviorMap.get(data.rowLabels[i]) || 'benign';
        if (level === behaviorFilter) {
          filteredIndices.push(i);
        }
      }
      const n = Math.min(topN, filteredIndices.length);
      const sliced = filteredIndices.slice(0, n);
      return {
        matrix: sliced.map(i => matrix[i]),
        labels: data.labels,
        rowLabels: sliced.map(i => data.rowLabels[i]),
        hostnames: sliced.map(i => data.hostnames?.[i] ?? null),
      };
    }

    const n = Math.min(topN, rows);
    return {
      matrix: matrix.slice(0, n),
      labels: data.labels,
      rowLabels: data.rowLabels.slice(0, n),
      hostnames: (data.hostnames ?? []).slice(0, n),
    };
  }, [data, topN, behaviorFilter, ipBehaviorMap]);

  // Draw heatmap canvas
  useEffect(() => {
    const fd = filteredData;
    if (!fd || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const { matrix, labels, rowLabels } = fd;
    const numCols = labels.length;
    const numRows = rowLabels.length;
    
    if (numCols === 0 || numRows === 0) return;

    // Responsive canvas sizing based on container width
    const containerWidth = canvas.parentElement ? canvas.parentElement.clientWidth - 32 : 800;
    const cellW_target = 60;
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
        ctx.fillStyle = heatmapColor(intensity);
        ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
        if (intensity > 0.8) {
          ctx.shadowColor = heatmapColor(intensity).replace(/[\d.]+\)$/, '0.6)');
          ctx.shadowBlur = 4;
          ctx.fillRect(j * cellW, i * cellH, cellW - 1, cellH - 1);
          ctx.shadowBlur = 0;
        }
      }
    }

    // Draw behavioral classification bars (left of IP labels)
    for (let i = 0; i < rowLabels.length; i++) {
      const ip = rowLabels[i];
      const level = ipBehaviorMap.get(ip) || null;
      if (level && level in BEHAVIOR_COLORS) {
        ctx.fillStyle = BEHAVIOR_COLORS[level as keyof typeof BEHAVIOR_COLORS];
        ctx.fillRect(0, i * cellH, 3, cellH - 1);
      }
    }

    // Draw IP labels (left column)
    const hostnames = (data?.hostnames || data?.hostnames_y || [])
    ctx.fillStyle = CYBER.textMuted;
    ctx.font = '9px monospace';
    ctx.textAlign = 'right';
    for (let i = 0; i < rowLabels.length; i++) {
      const ipLabel = format_ip(rowLabels[i], hostnames[i] || null);
      const short = ipLabel.length > 25 ? ipLabel.substring(0, 22) + '...' : ipLabel;
      ctx.fillText(short, cellW - 4, i * cellH + cellH / 2 + 3);
    }

    // Draw hour labels (bottom row)
    ctx.textAlign = 'center';
    for (let j = 0; j < labels.length; j++) {
      ctx.fillText(labels[j], j * cellW + cellW / 2, canvas.height - 2);
    }
  }, [filteredData]);

  // Draw color legend gradient bar
  useEffect(() => {
    if (!legendCanvasRef.current || !filteredData) return;
    const canvas = legendCanvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Compute max value for legend labels
    let maxVal = 0;
    for (const row of filteredData.matrix) {
      for (const v of row) {
        if (v > maxVal) maxVal = v;
      }
    }

    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    // Draw gradient
    const steps = w;
    for (let x = 0; x < steps; x++) {
      const intensity = x / (steps - 1);
      ctx.fillStyle = heatmapColor(intensity);
      ctx.fillRect(x, 0, 1, h);
    }

    // Draw rounded border
    ctx.strokeStyle = CYBER.border;
    ctx.lineWidth = 1;
    const radius = 4;
    ctx.beginPath();
    ctx.moveTo(radius, 0);
    ctx.lineTo(w - radius, 0);
    ctx.quadraticCurveTo(w, 0, w, radius);
    ctx.lineTo(w, h - radius);
    ctx.quadraticCurveTo(w, h, w - radius, h);
    ctx.lineTo(radius, h);
    ctx.quadraticCurveTo(0, h, 0, h - radius);
    ctx.lineTo(0, radius);
    ctx.quadraticCurveTo(0, 0, radius, 0);
    ctx.closePath();
    ctx.stroke();

    // Draw value labels
    ctx.fillStyle = CYBER.textMuted;
    ctx.font = '9px monospace';
    ctx.textAlign = 'left';
    ctx.fillText('0', 0, h + 14);
    ctx.textAlign = 'center';
    ctx.fillText(Math.round(maxVal / 2).toLocaleString(), w / 2, h + 14);
    ctx.textAlign = 'right';
    ctx.fillText(maxVal.toLocaleString(), w, h + 14);
  }, [filteredData]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!filteredData || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const { matrix, labels, rowLabels, hostnames } = filteredData;
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
        hostname: hostnames?.[row] || null,
        hour: labels[col],
      });
    } else {
      setTooltip(null);
    }
  };

  if (isLoading) {
    return <HeatmapSkeleton />;
  }

  if (isError && error) {
    return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Traffic Heatmap" />;
  }

  return (
    <div className="space-y-4">
      {/* Header row with controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <Flame size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Traffic Heatmap</h2>
          <span className="text-xs text-cyber-textMuted font-mono">IP x Hour Activity</span>
        </div>

        {/* Top-N dropdown */}
        <div className="flex items-center gap-2">
          <label className="text-xs text-cyber-textMuted font-mono">Show Top N IPs:</label>
          <div className="relative">
            <select
              value={topN}
              onChange={(e) => setTopN(Number(e.target.value))}
              className="appearance-none bg-cyber-panel border border-cyber-border rounded px-3 py-1 pr-7 text-xs font-mono text-cyber-text focus:border-cyber-accent focus:outline-none cursor-pointer"
            >
              {TOP_N_OPTIONS.map((n) => (
                <option key={n} value={n}>Top {n}</option>
              ))}
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-cyber-textMuted pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Color legend — prominent bar with labels, placed above the grid */}
      <div className="cyber-card p-3">
        <div className="text-xs text-cyber-textMuted font-mono mb-2">Events per hour</div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-cyber-textMuted font-mono w-10 text-right">0</span>
          <div className="flex-1">
            <canvas
              ref={legendCanvasRef}
              width={600}
              height={24}
              className="w-full rounded"
              style={{ imageRendering: 'pixelated' }}
            />
          </div>
          <span className="text-[11px] text-cyber-textMuted font-mono w-14">
            {filteredData ? (() => {
              let m = 0;
              for (const row of filteredData.matrix)
                for (const v of row) if (v > m) m = v;
              return m.toLocaleString();
            })() : ''}
          </span>
        </div>
      </div>

      <div className="cyber-card p-4 relative">
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
            <div className="font-semibold">{format_ip(tooltip.ip, tooltip.hostname || null)}</div>
            <div className="text-cyber-textMuted">{tooltip.hour}</div>
            <div className="text-cyber-accent">{tooltip.val.toLocaleString()} events</div>
          </div>
        )}
      </div>
    </div>
  );
}