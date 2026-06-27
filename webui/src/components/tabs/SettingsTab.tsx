// ═══════════════════════════════════════════════════
// Settings Tab - Configuration management
// ═══════════════════════════════════════════════════

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api';
import { Settings as SettingsIcon, Save, RefreshCw, Palette } from 'lucide-react';
import { useState, useEffect } from 'react';
import { useTheme } from '@/utils/useTheme';
import { THEMES, THEME_LIST, ThemeName } from '@/utils/themes';

import { SettingsSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function SettingsTab() {
  const queryClient = useQueryClient();
  const { theme, setTheme } = useTheme();
  const [settings, setSettings] = useState<Record<string, string | number>>({});
  const [saved, setSaved] = useState(false);

  // Load current settings
  const { data: settingsData, isLoading, isError, error, refetch } = useQuery<Record<string, string | number>>({
    queryKey: ['settings'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/settings');
        if (res.ok) return await res.json();
        return {};
      } catch { return {}; }
    },
  });

  // All hooks MUST be called before any early returns (Rules of Hooks)
  useEffect(() => {
    if (settingsData) setSettings(settingsData);
  }, [settingsData]);

  const saveSettings = useMutation({
    mutationFn: async (data: Record<string, string | number>) => {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error('Failed to save');
      return res.json();
    },
    onSettled: () => {
      setSaved(true);
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setTimeout(() => setSaved(false), 3000);
    },
  });

  if (isLoading) return <SettingsSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Settings" />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md" style={{ background: `color-mix(in srgb, var(--theme-accent) 10%, transparent)`, border: `1px solid color-mix(in srgb, var(--theme-accent) 20%, transparent)` }}>
            <SettingsIcon size={16} style={{ color: 'var(--theme-accent)' }} className="flex items-center justify-center" />
          </div>
          <h2 className="text-lg font-bold">Settings</h2>
        </div>
        {saved && <span className="text-xs" style={{ color: 'var(--theme-green)' }}>✓ Saved successfully</span>}
      </div>

      {/* Appearance — Theme Selector */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--theme-text-muted)' }}>
          <span className="flex items-center gap-2">
            <Palette size={14} /> Appearance
          </span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {THEME_LIST.map((t) => {
            const isActive = theme === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTheme(t.id)}
                className={`relative rounded-lg border-2 p-3 text-left transition-all duration-200 ${
                  isActive ? 'ring-2 ring-offset-1 ring-offset-transparent outline outline-1' : 'hover:border-opacity-60'
                }`}
                style={{
                  background: t.bg,
                  borderColor: isActive ? t.accent : t.border,
                  outlineColor: isActive ? t.accent : 'transparent',
                  boxShadow: isActive ? `0 0 12px ${t.accent}33` : 'none',
                }}
              >
                {/* Swatch bar */}
                <div className="flex gap-1 mb-2">
                  {t.swatch.map((c, i) => (
                    <div
                      key={i}
                      className="h-2 flex-1 rounded-full"
                      style={{ background: c }}
                    />
                  ))}
                </div>

                {/* Name */}
                <div className="font-semibold text-sm mb-0.5" style={{ color: t.text }}>
                  {t.name}
                  {isActive && (
                    <span className="ml-1.5 text-xs font-mono" style={{ color: t.accent }}>
                      ● Active
                    </span>
                  )}
                </div>

                {/* Preview colors row */}
                <div className="flex gap-1 mt-1.5">
                  {[t.accent, t.secondary, t.green].map((c, i) => (
                    <div
                      key={i}
                      className="w-4 h-4 rounded-sm border"
                      style={{
                        background: c,
                        borderColor: 'color-mix(in srgb, var(--theme-border) 50%, transparent)',
                      }}
                      title={['accent', 'secondary', 'success'][i]}
                    />
                  ))}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Detection Tuning */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Detection Tuning</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Port Scan Window (seconds)</label>
            <input
              type="number"
              value={settings.portscan_window || 60}
              onChange={(e) => setSettings({ ...settings, portscan_window: parseInt(e.target.value) })}
              className="cyber-input"
            />
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Brute Force Threshold</label>
            <input
              type="number"
              value={settings.bruteforce_threshold || 50}
              onChange={(e) => setSettings({ ...settings, bruteforce_threshold: parseInt(e.target.value) })}
              className="cyber-input"
            />
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Sensitivity</label>
            <select
              value={settings.sensitivity || 'medium'}
              onChange={(e) => setSettings({ ...settings, sensitivity: e.target.value })}
              className="cyber-select"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Syn Threshold</label>
            <input
              type="number"
              value={settings.syn_threshold || 100}
              onChange={(e) => setSettings({ ...settings, syn_threshold: parseInt(e.target.value) })}
              className="cyber-input"
            />
          </div>
        </div>
      </div>

      {/* Save Button */}
      <button
        onClick={() => saveSettings.mutate(settings)}
        className="cyber-btn flex items-center gap-2"
      >
        <Save size={14} /> Save Settings
      </button>

      {/*  Settings */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4"> Integration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Elasticsearch Host</label>
            <input
              type="text"
              placeholder="http://192.168.99.12:9200"
              className="cyber-input font-mono text-xs"
            />
          </div>
          <div>
            <label className="text-xs text-cyber-textMuted block mb-1">Index Pattern</label>
            <input
              type="text"
              value="-firewall-*"
              disabled
              className="cyber-input font-mono text-xs bg-cyber-darker text-cyber-textMuted"
            />
          </div>
        </div>
      </div>

      {/* Data Management */}
      <div className="cyber-card p-4">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Data Management</h3>
        <div className="flex gap-3">
          <button
            onClick={() => queryClient.invalidateQueries()}
            className="cyber-btn flex items-center gap-2"
          >
            <RefreshCw size={14} /> Refresh All Data
          </button>
          <button className="cyber-btn-danger flex items-center gap-2">
            Clear Cache
          </button>
        </div>
      </div>
    </div>
  );
}
