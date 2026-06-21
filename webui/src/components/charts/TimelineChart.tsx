// TimelineChart - uPlot time series chart for event data
import React, { useRef, useEffect } from 'react';
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
  grid: 'rgba(148, 163, 184, 0.1)',
  tick: 'rgba(148, 163, 184, 0.2)',
  label: '#94a3b8',
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

  useEffect(() => {
    if (!containerRef.current || !data.length) return;

    const times = new Float64Array(data.map(d => d.time));
    const values = new Float64Array(data.map(d => d.value));

    const opts: any = {
      title,
      width: containerRef.current.clientWidth,
      height,
      padding: [10, 20, 30, 60],
      scales: {
        x: {
          time: true,
          range: [times[0], times[times.length - 1]],
        },
      },
      axes: [
        null,
        {
          scale: 'x',
          space: 50,
          grid: { show: false },
          ticks: { show: false },
          values: (splits: number[]) => {
            return splits.map(val => {
              const date = new Date(val * 1000);
              const hours = date.getHours().toString().padStart(2, '0');
              const minutes = date.getMinutes().toString().padStart(2, '0');
              return `${hours}:${minutes}`;
            });
          },
          font: 'Inter, system-ui, sans-serif',
          stroke: COLORS.label,
        },
        {
          scale: 'y',
          side: 0,
          stroke: COLORS.label,
          font: 'Inter, system-ui, sans-serif',
          grid: { stroke: COLORS.grid, width: 1 },
          ticks: { stroke: COLORS.tick, width: 1 },
        },
      ],
      series: [
        {},
        {
          label: 'Events',
          stroke: COLORS.events,
          width: 2,
          fill: COLORS.events + '20',
          points: { show: false },
        },
      ],
      cursor: {
        lock: true,
        points: { size: 5, width: 2 },
        y: { show: false },
      },
      legend: { show: true },
    };

    const seriesData = [times, values];

    if (chartRef.current) {
      chartRef.current.setData(seriesData);
    } else {
      chartRef.current = new uPlot(opts, seriesData, containerRef.current);
    }

    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, [data, title, height]);

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