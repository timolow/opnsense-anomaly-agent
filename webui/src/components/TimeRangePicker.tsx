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
    return date.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
  };

  return (
    <div className="relative">
      <div className="flex items-center gap-1 bg-slate-900/80 rounded-lg p-1 border border-slate-700/50">
        {(Object.keys(timeRanges) as TimeRange[]).map((range) => (
          <button
            key={range}
            onClick={() => handleTimeRangeChange(range)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
              timeRange === range && !showCustom
                ? 'bg-cyan-500/20 text-cyan-400 shadow-sm shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            {timeRanges[range].label}
          </button>
        ))}
        <button
          onClick={() => setShowCustom(!showCustom)}
          className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
            timeRange === 'custom'
              ? 'bg-cyan-500/20 text-cyan-400'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Custom
        </button>
      </div>
      {showCustom && (
        <div className="absolute top-full right-0 mt-2 p-4 bg-slate-900 border border-slate-700 rounded-lg shadow-xl z-50">
          <div className="flex flex-col gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">From</label>
              <input
                type="datetime-local"
                value={startDate || formatDateTime(new Date(Date.now() - 86400000))}
                onChange={e => setStartDate(e.target.value)}
                className="w-full bg-slate-800 text-slate-300 text-xs rounded px-2 py-1 border border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">To</label>
              <input
                type="datetime-local"
                value={endDate || formatDateTime(new Date())}
                onChange={e => setEndDate(e.target.value)}
                className="w-full bg-slate-800 text-slate-300 text-xs rounded px-2 py-1 border border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex gap-2 mt-2">
              <button
                onClick={handleCustomRangeChange}
                className="px-3 py-1 rounded text-xs font-medium bg-cyan-500 text-white hover:bg-cyan-600"
              >
                Apply
              </button>
              <button
                onClick={() => setShowCustom(false)}
                className="px-3 py-1 rounded text-xs font-medium bg-slate-700 text-slate-300 hover:bg-slate-600"
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