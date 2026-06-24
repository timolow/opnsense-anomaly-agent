// TimeRangePicker - Grafana-like time range selection
import React from 'react';
import { useStore } from '../../store';

const PRESETS = [
  { label: '1H', value: '1h' },
  { label: '6H', value: '6h' },
  { label: '24H', value: '24h' },
  { label: '7D', value: '7d' },
  { label: '30D', value: '30d' },
];

export default function TimeRangePicker() {
  const { timeRange, setTimeRange } = useStore();

  return (
    <div className="flex items-center gap-1 bg-cyber-panel border border-cyber-border rounded-lg p-1">
      {PRESETS.map(({ label, value }) => (
        <button
          key={value}
          onClick={() => setTimeRange(value as any)}
          className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
            timeRange === value
              ? 'bg-cyber-accent/20 text-cyber-accent'
              : 'text-cyber-textMuted hover:text-cyber-text'
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}