// ═══════════════════════════════════════════════════
// Logs Query Tab - Query logs
// ═══════════════════════════════════════════════════

import { useState } from 'react';
import { Database, Search, Filter } from 'lucide-react';
import type { Event } from '@/types';

export default function LogsQueryTab() {
  const [srcIp, setSrcIp] = useState('');
  const [days, setDays] = useState('7');
  const [results, setResults] = useState<Event[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSearch = async () => {
    setLoading(true);
    setError('');
    setResults([]);
    
    try {
      const res = await fetch('/api//events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: {
            bool: {
              should: [
                { term: { 'source.ip': srcIp } },
                { term: { 'destination.ip': srcIp } },
              ],
              minimum_should_match: 1,
            },
          },
          size: 100,
          sort: [{ '@timestamp': { order: 'desc' } }],
          _source: true,
        }),
      });
      
      if (!res.ok) throw new Error(`Search failed: ${res.status}`);
      const data = await res.json();
      setResults(data.hits || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <Database size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">Query Logs</h2>
      </div>

      {/* Search Form */}
      <div className="cyber-card p-4 scanlines">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-3">
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Source IP</label>
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
              <input
                type="text"
                placeholder="e.g. 192.168.1.100"
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                className="cyber-input pl-9 font-mono"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Days Back</label>
            <input
              type="number"
              min="1"
              max="90"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="cyber-input"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={handleSearch}
              disabled={loading || !srcIp}
              className="cyber-btn w-full flex items-center justify-center gap-2"
            >
              <Search size={14} /> Search
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      <div className="cyber-card p-4 scanlines">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
          </div>
        ) : error ? (
          <div className="text-cyber-red text-sm text-center py-8">{error}</div>
        ) : results.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">
            <Filter size={32} className="mx-auto mb-2 opacity-30" />
            No results found
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm text-cyber-textMuted">{results.length} results</span>
            </div>
            <div className="overflow-x-auto">
              <table className="cyber-table text-xs">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Interface</th>
                    <th>Rule</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((event, i) => (
                    <tr key={i} className="hover:bg-cyber-panel/30">
                      <td className="text-cyber-textMuted">{new Date(event['@timestamp']).toLocaleString()}</td>
                      <td>
                        <span className={`cyber-badge ${event.event.action === 'pass' ? 'cyber-badge-pass' : 'cyber-badge-block'}`}>
                          {event.event.action}
                        </span>
                      </td>
                      <td className="font-mono">{event.network.protocol?.toUpperCase()}</td>
                      <td className="font-mono">{event.source.ip}</td>
                      <td className="font-mono">{event.destination.ip}</td>
                      <td className="font-mono">{event.destination.port}</td>
                      <td className="font-mono text-xs">{event.interface.name}</td>
                      <td className="font-mono text-xs">{event.rule.id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
