// UPlot wrapper for React — time series charts with zoom/pan/brush
import React, { useRef, useEffect, useCallback } from 'react';
import uPlot from 'uplot';

// Time range types
export type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';

export interface TimeRangeState {
  range: TimeRange;
  customStart?: Date;
  customEnd?: Date;
}

export interface DataPoint {
  time: number | Date;
  values: number[];
}

export interface SeriesConfig {
  label: string;
  color: string;
  type?: 'lines' | 'bars';
  stroke?: string;
  width?: number;
}

export interface UPlotWrapperProps {
  title: string;
  data: DataPoint[];
  series: SeriesConfig[];
  height?: number;
  showBrush?: boolean;
  className?: string;
  isLoading?: boolean;
}

// Dark theme styles
const DARK_THEME = {
  bg: '#0f172a',
  grid: 'rgba(148, 163, 184, 0.1)',
  tick: 'rgba(148, 163, 184, 0.2)',
  label: '#94a3b8',
  font: 'Inter, system-ui, sans-serif',
};

const UPlotWrapper: React.FC<UPlotWrapperProps> = ({
  title,
  data,
  series,
  height = 300,
  showBrush = false,
  className = '',
  isLoading = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<uPlot | null>(null);

  // Parse time range from data
  const getTimeRange = useCallback((data: DataPoint[]) => {
    if (!data.length) return { start: 0, end: 0 };
    const times = data.map(d =>
      typeof d.time === 'number' ? d.time : new Date(d.time).getTime() / 1000
    );
    return { start: Math.min(...times), end: Math.max(...times) };
  }, []);

  // Build uPlot series config
  const buildSeriesConfig = useCallback((series: SeriesConfig[]) => {
    return [
      {}, // x-axis series (time)
      ...series.map((s, i) => ({
        label: s.label,
        stroke: s.color,
        width: s.width || 2,
        fill: s.color + '20', // 20% opacity for area fill
        points: { show: false }, // Hide points by default
      })),
    ];
  }, []);

  // Format time axis labels
  const timeFormatter = useCallback((value: number) => {
    const date = new Date(value * 1000);
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
  }, []);

  // Update chart when data changes
  useEffect(() => {
    if (!containerRef.current || !data.length) return;

    const { start, end } = getTimeRange(data);
    const times = data.map(d =>
      typeof d.time === 'number' ? d.time : new Date(d.time).getTime() / 1000
    );

    // Build series data arrays
    const seriesData = [times]; // x-axis first
    for (let i = 0; i < series.length; i++) {
      seriesData.push(data.map(d => d.values[i] || 0));
    }

    const opts: uPlot.Options = {
      title,
      width: containerRef.current.clientWidth,
      height,
      padding: [10, 20, 30, 60], // top, right, bottom, left
      scales: {
        x: {
          time: true,
          range: [start, end],
        },
      },
      axes: [
        null, // No top axis
        {
          scale: 'x',
          space: 50,
          grid: { show: false },
          ticks: { show: false },
          values: timeFormatter,
          font: DARK_THEME.font,
          stroke: DARK_THEME.label,
        },
        {
          scale: 'y',
          side: 0,
          stroke: DARK_THEME.label,
          font: DARK_THEME.font,
          grid: {
            stroke: DARK_THEME.grid,
            width: 1,
          },
          ticks: {
            stroke: DARK_THEME.tick,
            width: 1,
          },
        },
      ],
      series: buildSeriesConfig(series),
      cursor: {
        lock: true,
        points: { size: 5, width: 2 },
        y: { show: false },
      },
      legend: {
        show: true,
        padding: 10,
        mkCell(values, seriesIdx, itemIdx) {
          const el = document.createElement('span');
          el.className = 'u-legend-item';
          el.style.color = series[seriesIdx]?.color || '#fff';
          el.textContent = series[seriesIdx]?.label || '';
          return el;
        },
      },
    };

    if (showBrush) {
      opts.select = {
        show: true,
        drag: {
          setScale: true,
          zoom: true,
        },
      };
    }

    // Destroy previous chart if exists
    if (chartRef.current) {
      chartRef.current.destroy();
    }

    // Create new chart
    chartRef.current = new uPlot(opts, seriesData, containerRef.current);

    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, [data, series, title, height, showBrush, getTimeRange, buildSeriesConfig, timeFormatter]);

  // Handle resize
  useEffect(() => {
    const handleResize = () => {
      if (chartRef.current && containerRef.current) {
        chartRef.current.setSize({
          width: containerRef.current.clientWidth,
          height,
        });
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [height]);

  if (isLoading) {
    return (
      <div className={`bg-slate-900 rounded-lg p-4 ${className}`}>
        <div className="flex items-center justify-center h-[300px]">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400"></div>
        </div>
      </div>
    );
  }

  return (
    <div className={`bg-slate-900 rounded-lg p-4 ${className}`}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-300">{title}</h3>
      </div>
      <div ref={containerRef} className="w-full" />
    </div>
  );
};

export default UPlotWrapper;