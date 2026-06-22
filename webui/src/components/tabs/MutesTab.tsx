// ═══════════════════════════════════════════════════
// Mutes Tab - IP mute management
// ═══════════════════════════════════════════════════

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import type { MutesData } from '@/types';
import { Ban, Plus, Trash2, Search } from 'lucide-react';
import { useState } from 'react';

export default function MutesTab() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ ip: '', duration: '1h', reason: '' });
  const [search, setSearch] = useState('');

  const { data: mutes = [] } = useQuery<MutesData[]>({
    queryKey: ['mutes'],
    queryFn: api.mutes,
    refetchInterval: 15000,
  });

  const createMute = useMutation({
    mutationFn: api.createMute,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mutes'] });
      setForm({ ip: '', duration: '1h', reason: '' });
      setShowForm(false);
    },
  });

  const deleteMute = useMutation({
    mutationFn: (id: string) => api.deleteMute(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mutes'] });
    },
  });

  const filtered = mutes.filter((m) =>
    m.ip.includes(search) || m.reason.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
            <Ban size={16} className="text-cyber-purple" />
          </div>
          <h2 className="text-lg font-bold">Mutes</h2>
          <span className="text-xs text-cyber-textMuted font-mono">{mutes.length} active</span>
        </div>
        <button onClick={() => setShowForm(!showForm)} className="cyber-btn flex items-center gap-2">
          <Plus size={14} /> Add Mute
        </button>
      </div>

      {/* Add Mute Form */}
      {showForm && (
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder="IP Address"
              value={form.ip}
              onChange={(e) => setForm({ ...form, ip: e.target.value })}
              className="cyber-input"
            />
            <select
              value={form.duration}
              onChange={(e) => setForm({ ...form, duration: e.target.value })}
              className="cyber-select"
            >
              <option value="15m">15 minutes</option>
              <option value="1h">1 hour</option>
              <option value="6h">6 hours</option>
              <option value="24h">24 hours</option>
              <option value="7d">7 days</option>
              <option value="30d">30 days</option>
            </select>
            <input
              type="text"
              placeholder="Reason"
              value={form.reason}
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
              className="cyber-input"
            />
          </div>
          <div className="flex gap-2 mt-3">
            <button
              onClick={() => createMute.mutate(form)}
              disabled={!form.ip}
              className="cyber-btn-success"
            >
              Apply Mute
            </button>
            <button onClick={() => setShowForm(false)} className="cyber-btn">Cancel</button>
          </div>
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-textMuted" />
        <input
          type="text"
          placeholder="Search mutes..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="cyber-input pl-9"
        />
      </div>

      {/* Mutes Table */}
      <div className="cyber-card p-4 scanlines">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-cyber-textMuted">No active mutes</div>
        ) : (
          <div className="cyber-table-responsive"><table className="cyber-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Duration</th>
                <th>Reason</th>
                <th>Created</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((mute) => (
                <tr key={mute.id}>
                  <td className="font-mono">{mute.ip}</td>
                  <td><span className="cyber-badge cyber-badge-info">{mute.duration}</span></td>
                  <td className="max-w-xs truncate">{mute.reason}</td>
                  <td className="text-cyber-textMuted">{mute.created}</td>
                  <td className="text-cyber-textMuted">{mute.expires}</td>
                  <td>
                    <button
                      onClick={() => deleteMute.mutate(mute.id)}
                      className="text-cyber-textMuted hover:text-cyber-red transition-colors"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>
    </div>
  );
}
