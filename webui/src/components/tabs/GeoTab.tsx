// ═══════════════════════════════════════════════════
// Geo Tab - Geographic visualization of traffic
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { GeoData } from '@/types';
import { Globe } from 'lucide-react';

const FLAG_MAP: Record<string, string> = {
  'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪', 'GB': '🇬🇧',
  'FR': '🇫🇷', 'JP': '🇯🇵', 'BR': '🇧🇷', 'IN': '🇮🇳', 'KR': '🇰🇷',
  'AU': '🇦🇺', 'CA': '🇨🇦', 'NL': '🇳🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
  'IR': '🇮🇷', 'KP': '🇰🇵', 'UA': '🇺🇦', 'SE': '🇸🇪', 'NO': '🇳🇴',
};

import { GeoSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function GeoTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<GeoData>({
    queryKey: ['geo'],
    queryFn: api.geo,
    refetchInterval: 60000,
  });

  if (isLoading) return <GeoSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Geography" />;

  const topCountries = data.countries.slice(0, 20);
  const totalEvents = topCountries.reduce((s, c) => s + c.count, 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
          <Globe size={16} className="text-cyber-accent" />
        </div>
        <h2 className="text-lg font-bold">Geographic Distribution</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{totalEvents.toLocaleString()} total events</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Country bars */}
        <div className="cyber-card p-4 scanlines">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Top Sources</h3>
          <div className="space-y-3">
            {topCountries.map((c) => {
              const pct = totalEvents > 0 ? (c.count / totalEvents) * 100 : 0;
              return (
                <div key={c.country} className="flex items-center gap-3">
                  <span className="text-lg w-8 text-center">{FLAG_MAP[c.country] || '🌐'}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{c.country}</span>
                      <span className="text-xs font-mono text-cyber-textMuted">{c.count.toLocaleString()}</span>
                    </div>
                    <div className="cyber-progress-track">
                      <div
                        className="cyber-progress-fill"
                        style={{
                          width: `${pct}%`,
                          background: `linear-gradient(90deg, ${c.color}, ${c.color}80)`,
                          boxShadow: `0 0 8px ${c.color}40`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Visual grid */}
        <div className="cyber-card p-4 scanlines">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Intensity Map</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {topCountries.slice(0, 15).map((c) => (
              <div
                key={c.country}
                className="cyber-card p-3 cyber-card-hover cursor-pointer"
                style={{ borderLeft: `3px solid ${c.color}` }}
              >
                <div className="text-2xl text-center mb-1">{FLAG_MAP[c.country] || '🌐'}</div>
                <div className="text-xs font-medium text-center">{c.country}</div>
                <div className="text-xs font-mono text-center text-cyber-textMuted">{c.count.toLocaleString()}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
