// UPlot wrapper for React — time series charts with zoom/pan/brush
import React, { useRef, useEffect, useCallback } from 'react';
import uPlot from 'uplot';
import { CHART_THEME } from '@/utils/colors';

// Types
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
  stroke?: string;
  width?: number;
}

export interface UPlotWrapperProps {
  title: string;
  data: DataPoint[];
  series: SeriesConfig[];
  height?: number;
  className?: string;
  isLoading?: boolean;
}

const DARK_THEME = CHART_THEME;

const UPlotWrapper: React.FC<UPlotWrapperProps> = ({
  title,
  data,
  series,
  height = 300,
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
      ...series.map(s => ({
        label: s.label,
        stroke: s.color,
        width: s.width || 2,
        fill: s.color + '20', // 20% opacity for area fill
        points: { show: false },
      })),
    ];
  }, []);

  // Format time axis labels
  const timeFormatter = useCallback(
    (u: uPlot, val: number, self: uPlot.Axis) => {
      const date = new Date(val * 1000);
      const hours = date.getHours().toString().padStart(2, '0');
      const minutes = date.getMinutes().toString().padStart(2, '0');
      return `${hours}:${minutes}`;
    },
    []
  );

  // Initialize/update chart
  useEffect(() => {
    if (!containerRef.current || !data.length) return;

    const { start, end } = getTimeRange(data);
    const times = new Float64Array(
      data.map(d =>
        typeof d.time === 'number' ? d.time : new Date(d.time).getTime() / 1000
      )
    );

    // Build series data arrays as Float64Array
    const seriesData = [times]; // x-axis first
    for (let i = 0; i < series.length; i++) {
      seriesData.push(new Float64Array(data.map(d => d.values[i] || 0)));
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
      },
    };

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
  }, [data, series, title, height, getTimeRange, buildSeriesConfig, timeFormatter]);

  if (isLoading) {
    return (
      <div className={`flex items-center justify-center ${className}`}>
        <div className="w-full h-[300px] bg-cyber-dark/50 rounded-lg border border-cyber-border/50 animate-pulse" />
      </div>
    );
  }

  if (!data.length) {
    return (
      <div className={`flex items-center justify-center ${className}`}>
        <div className="w-full h-[300px] bg-cyber-dark/50 rounded-lg border border-cyber-border/50 flex items-center justify-center">
          <span className="text-cyber-textMuted text-sm">No data available</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative ${className}`}>
      <div ref={containerRef} className="w-full" style={{ height }} />
    </div>
  );
};

export default UPlotWrapper;