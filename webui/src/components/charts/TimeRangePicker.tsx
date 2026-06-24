// TimeRangePicker - Grafana-like time range selection
import React, { useState } from 'react';
import { useDashboardStore } from '../../store';
import type { TimeRange } from './UPlotChart';

const PRESETS: { label: string; range: TimeRange }[] = [
  { label: '1H', range: '1h' },
  { label: '6H', range: '6h' },
  { label: '24H', range: '24h' },
  { label: '7D', range: '7d' },
  { label: '30D', range: '30d' },
  { label: 'ALL', range: 'custom' },
];

const TimeRangePicker: React.FC = () => {
  const { timeRange, setTimeRange } = useDashboardStore();
  const [showCustom, setShowCustom] = useState(false);
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');

  const handlePreset = (range: TimeRange) => {
    if (range === 'custom') {
      setShowCustom(true);
      return;
    }
    setTimeRange({ range, customStart: undefined, customEnd: undefined });
    setShowCustom(false);
  };

  const handleCustomApply = () => {
    if (!customStart || !customEnd) return;
    setTimeRange({
      range: 'custom',
      customStart: new Date(customStart),
      customEnd: new Date(customEnd),
    });
    setShowCustom(false);
  };

  return (
    <div className="relative">
      <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg p-1">
        {PRESETS.map(({ label, range }) => (
          <button
            key={range}
            onClick={() => handlePreset(range)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              timeRange.range === range && !showCustom
                ? 'bg-cyan-500 text-white'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Custom date picker dropdown */}
      {showCustom && (
        <div className="absolute top-full right-0 mt-2 p-4 bg-slate-900 border border-slate-700 rounded-lg shadow-xl z-50">
          <div className="flex flex-col gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">From</label>
              <input
                type="datetime-local"
                value={customStart}
                onChange={e => setCustomStart(e.target.value)}
                className="w-full bg-slate-800 text-slate-300 text-xs rounded px-2 py-1 border border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">To</label>
              <input
                type="datetime-local"
                value={customEnd}
                onChange={e => setCustomEnd(e.target.value)}
                className="w-full bg-slate-800 text-slate-300 text-xs rounded px-2 py-1 border border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex gap-2 mt-2">
              <button
                onClick={handleCustomApply}
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