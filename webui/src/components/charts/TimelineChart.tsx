// TimelineChart - uPlot time series chart for event data
import React, { useRef, useEffect, useMemo } from 'react';
import uPlot from 'uplot';
import { Activity } from 'lucide-react';

interface TimelineData {
  time: number; // Unix timestamp
  value: number;
}

interface TimelineChartProps {
  title?: string;
  data: TimelineData[];
  height?: number;
  isLoading?: boolean;
  className?: string;
  isLive?: boolean;
}

const COLORS = {
  events: '#06b6d4',
  eventsFill: 'rgba(6, 182, 212, 0.3)',
  blocked: '#ff1744',
  blockedFill: 'rgba(255, 23, 68, 0.2)',
  grid: 'rgba(148, 163, 184, 0.15)',
  tick: 'rgba(148, 163, 184, 0.3)',
  label: '#94a3b8',
  bg: '#0d1117',
};

const TimelineChart: React.FC<TimelineChartProps> = ({
  title = 'Event Timeline',
  data = [],
  height = 300,
  isLoading = false,
  className = '',
  isLive = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<any>(null);

  // Pre-compute series data as Float64Arrays
  const seriesData = useMemo(() => {
    if (!data.length) return null;
    const times = new Float64Array(data.map(d => d.time));
    const values = new Float64Array(data.map(d => d.value));
    return [times, values];
  }, [data]);

  useEffect(() => {
    if (!containerRef.current || !seriesData) return;

    const width = containerRef.current.clientWidth;
    const [times, values] = seriesData;

    // Compute y-axis range - use log-friendly scale for extreme variance
    const maxVal = Math.max(...Array.from(values));
    const minVal = Math.min(...Array.from(values).filter(v => v > 0));
    const yMin = 0;
    const yMax = maxVal * 1.1; // 10% headroom

    const opts: any = {
      title: '',
      width,
      height,
      padding: [12, 20, 40, 65],
      focus: {
        alpha: true,
      },
      scales: {
        x: {
          time: true,
          range: [times[0], times[times.length - 1]],
        },
        y: {
          range: [yMin, yMax],
        },
      },
      axes: [
        null, // x bottom
        {
          scale: 'x',
          space: 40,
          grid: { show: false },
          size: 35,
          values: (splits: number[] | number) => {
            const arr = Array.isArray(splits) ? splits : [splits];
            return arr.map(val => {
              const date = new Date(val * 1000);
              const h = date.getHours().toString().padStart(2, '0');
              const m = date.getMinutes().toString().padStart(2, '0');
              return `${h}:${m}`;
            });
          },
          font: '11px Inter, system-ui, monospace',
          stroke: COLORS.label,
          splits: (scaleMin: number, scaleMax: number, foundSplits: number[] | number) => {
            // foundSplits can be a number (count) or array depending on uPlot version
            const arr = Array.isArray(foundSplits) ? foundSplits : [];
            const target = Math.min(6, arr.length);
            if (target === 0) return arr;
            const step = Math.ceil(arr.length / target);
            return arr.filter((_: number, i: number) => i % step === 0);
          },
        },
        {
          scale: 'y',
          side: 0,
          size: 60,
          stroke: COLORS.label,
          font: '11px Inter, system-ui, monospace',
          grid: { stroke: COLORS.grid, width: 1 },
          ticks: { stroke: COLORS.tick, width: 1 },
          values: (v: number[] | number) => {
            const arr = Array.isArray(v) ? v : [v];
            return arr.map(n => {
              if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
              if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
              return Math.round(n).toString();
            });
          },
        },
      ],
      series: [
        {},
        {
          label: 'Events',
          stroke: COLORS.events,
          width: 2,
          fill: COLORS.eventsFill,
          points: {
            show: true,
            size: 2,
            stroke: COLORS.events,
            fill: '#0d1117',
            filter: (self: any, idx: number) => {
              // Show ~8 points max
              const total = self.data[1].length;
              const step = Math.max(1, Math.floor(total / 8));
              return idx % step === 0;
            },
          },
        },
      ],
      cursor: {
        lock: true,
        points: { size: 6, width: 2, stroke: COLORS.events, fill: '#0d1117' },
        y: { show: true, size: 6, stroke: COLORS.label, font: '11px monospace' },
      },
      legend: {
        show: true,
        mime: false,
      },
    };

    if (chartRef.current) {
      chartRef.current.setData(seriesData);
      // Resize in case container changed
      chartRef.current.resize(width, height, true);
    } else {
      chartRef.current = new uPlot(opts, seriesData, containerRef.current);
    }

    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, [seriesData, title, height]);

  if (isLoading) {
    return (
      <div className={`cyber-card p-4 ${className}`}>
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <Activity size={14} /> {title}
          {isLive && (
            <span className="flex items-center gap-1.5 ml-2 px-2 py-0.5 rounded text-xs font-mono bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              LIVE
            </span>
          )}
        </h3>
        <div className="w-full h-[300px] bg-slate-900/50 rounded-lg border border-slate-700/50 animate-pulse" />
      </div>
    );
  }

  if (!data.length) {
    return (
      <div className={`cyber-card p-4 ${className}`}>
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
          <Activity size={14} /> {title}
          {isLive && (
            <span className="flex items-center gap-1.5 ml-2 px-2 py-0.5 rounded text-xs font-mono bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              LIVE
            </span>
          )}
        </h3>
        <div className="w-full h-[300px] bg-slate-900/50 rounded-lg border border-slate-700/50 flex items-center justify-center">
          <span className="text-slate-500 text-sm">No timeline data available</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`cyber-card p-4 ${className}`}>
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Activity size={14} /> {title}
        {isLive && (
          <span className="flex items-center gap-1.5 ml-2 px-2 py-0.5 rounded text-xs font-mono bg-cyber-green/10 text-cyber-green border border-cyber-green/20">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
            LIVE
          </span>
        )}
      </h3>
      <div ref={containerRef} className="w-full" style={{ height }} />
    </div>
  );
};

export default TimelineChart;