// TimeRangePicker - Grafana-like time selection
import React, { useState } from 'react';
import { useStore, timeRanges, getTimeRangeTimestamps } from '../store';
import type { TimeRange, CustomTimeRange } from '../store';

interface TimeRangePickerProps {
  onTimeRangeChange?: (start: number, end: number) => void;
}

const TimeRangePicker: React.FC<TimeRangePickerProps> = ({ onTimeRangeChange }) => {
  const { timeRange, setTimeRange, customTimeRange, setCustomTimeRange } = useStore();
  const [showCustom, setShowCustom] = useState(false);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  const handleTimeRangeChange = (range: TimeRange) => {
    setTimeRange(range);
    const { start, end } = getTimeRangeTimestamps(range);
    onTimeRangeChange?.(start, end);
  };

  const handleCustomRangeChange = () => {
    if (!startDate || !endDate) return;
    const customRange: CustomTimeRange = {
      start: Math.floor(new Date(startDate).getTime() / 1000),
      end: Math.floor(new Date(endDate).getTime() / 1000),
    };
    setCustomTimeRange(customRange);
    setTimeRange('custom');
    onTimeRangeChange?.(customRange.start, customRange.end);
    setShowCustom(false);
  };

  const formatDateTime = (date: Date) => {
    return date.toISOString().slice(0, 16);
  };

  return (
    <div className="relative">
    <div className="flex items-center gap-1 bg-cyber-dark/80 rounded-lg p-1 border border-cyber-border/50 overflow-x-auto max-w-[calc(100vw-120px)] sm:max-w-none">
      {(Object.keys(timeRanges) as TimeRange[]).map((range) => (
        <button
          key={range}
          onClick={() => handleTimeRangeChange(range)}
          className={`px-2 md:px-3 py-2 min-h-[36px] text-xs font-medium rounded-md transition-all whitespace-nowrap flex-shrink-0 ${
            timeRange === range && !showCustom
              ? 'bg-cyber-accent/20 text-cyber-accent shadow-sm shadow-cyber-accent/20'
              : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panel/50'
          }`}
        >
          {timeRanges[range].label}
        </button>
      ))}
      <button
        onClick={() => setShowCustom(!showCustom)}
        className={`px-2 md:px-3 py-2 min-h-[36px] text-xs font-medium rounded-md transition-all whitespace-nowrap flex-shrink-0 ${
          timeRange === 'custom'
            ? 'bg-cyber-accent/20 text-cyber-accent'
            : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panel/50'
        }`}
      >
        Custom
      </button>
    </div>
    {showCustom && (
      <div className="absolute top-full right-0 mt-2 p-4 bg-cyber-dark border border-cyber-border rounded-lg shadow-xl z-50">
        <div className="flex flex-col gap-3">
          <div>
            <label className="block text-xs text-cyber-textMuted mb-1">From</label>
            <input
              type="datetime-local"
              value={startDate || formatDateTime(new Date(Date.now() - 86400000))}
              onChange={e => setStartDate(e.target.value)}
              className="w-full bg-cyber-panel text-cyber-text text-xs rounded px-2 py-1 border border-cyber-border focus:outline-none focus:border-cyber-accent"
            />
          </div>
          <div>
            <label className="block text-xs text-cyber-textMuted mb-1">To</label>
            <input
              type="datetime-local"
              value={endDate || formatDateTime(new Date())}
              onChange={e => setEndDate(e.target.value)}
              className="w-full bg-cyber-panel text-cyber-text text-xs rounded px-2 py-1 border border-cyber-border focus:outline-none focus:border-cyber-accent"
            />
          </div>
          <div className="flex gap-2 mt-2">
            <button
              onClick={handleCustomRangeChange}
              className="px-3 py-1 rounded text-xs font-medium bg-cyber-accent text-cyber-darker hover:bg-cyber-accentHover"
            >
              Apply
            </button>
            <button
              onClick={() => setShowCustom(false)}
              className="px-3 py-1 rounded text-xs font-medium bg-cyber-panel text-cyber-text hover:bg-cyber-panelHover"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    )}
  </div>
  );
};

export default TimeRangePicker;