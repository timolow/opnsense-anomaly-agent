// ═══════════════════════════════════════════════════
// GeoDataPanel - Interactive country breakdown with bar chart
// ═══════════════════════════════════════════════════

import * as L from 'leaflet';
import type { GeoCountry } from '@/types';
import { BarChart3, TrendingUp, Globe, MapPin } from 'lucide-react';

const FLAG_EMOJI: Record<string, string> = {
  'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪', 'GB': '🇬🇧',
  'FR': '🇫🇷', 'JP': '🇯🇵', 'BR': '🇧🇷', 'IN': '🇮🇳', 'KR': '🇰🇷',
  'AU': '🇦🇺', 'CA': '🇨🇦', 'NL': '🇳🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
  'IR': '🇮🇷', 'KP': '🇰🇵', 'UA': '🇺🇦', 'SE': '🇸🇪', 'NO': '🇳🇴',
  'EU': '🇪🇺', 'OTHER': '🌐', 'OTHERS': '🌐', 'Unknown': '❓',
  'SG': '🇸🇬', 'HK': '🇭🇰', 'TW': '🇹🇼', 'CH': '🇨🇭', 'BE': '🇧🇪',
  'AT': '🇦🇹', 'DK': '🇩🇰', 'FI': '🇫🇮', 'PL': '🇵🇱', 'CZ': '🇨🇿',
  'RO': '🇷🇴', 'BG': '🇧🇬', 'HR': '🇭🇷', 'SI': '🇸🇮', 'SK': '🇸🇰',
  'HU': '🇭🇺', 'PT': '🇵🇹', 'GR': '🇬🇷', 'IL': '🇮🇱', 'AE': '🇦🇪',
  'SA': '🇸🇦', 'QA': '🇶🇦', 'KW': '🇰🇼', 'TH': '🇹🇭', 'VN': '🇻🇳',
  'PH': '🇵🇭', 'MY': '🇲🇾', 'ID': '🇮🇩', 'NZ': '🇳🇿', 'ZA': '🇿🇦',
  'EG': '🇪🇬', 'NG': '🇳🇬', 'KE': '🇰🇪', 'MX': '🇲🇽', 'AR': '🇦🇷',
  'CL': '🇨🇱', 'CO': '🇨🇴', 'PE': '🇵🇪', 'TR': '🇹🇷', 'IS': '🇮🇸',
  'IE': '🇮🇪', 'LT': '🇱🇹', 'LV': '🇱🇻', 'EE': '🇪🇪', 'MD': '🇲🇩',
  'KZ': '🇰🇿', 'UZ': '🇺🇿', 'BY': '🇧🇾', 'GE': '🇬🇪', 'AM': '🇦🇲',
};

function countryFlag(code: string): string {
  return FLAG_EMOJI[code] || (() => {
    // Try to generate flag emoji from 2-letter country code
    if (code.length === 2) {
      const codePoints = code.split('').map(ch => 0x1F1E6 - 65 + ch.toUpperCase().charCodeAt(0));
      try {
        return String.fromCodePoint(...codePoints);
      } catch {
        return '🌐';
      }
    }
    return '🌐';
  })();
}

interface GeoDataPanelProps {
  countries: GeoCountry[];
  totalEvents: number;
  map: L.Map | null;
  maxVisible?: number;
}

// ─────────────────────────────────────────────
// Horizontal bar chart for country events
// ─────────────────────────────────────────────
export function GeoDataPanel({ countries, totalEvents, map, maxVisible = 15 }: GeoDataPanelProps) {
  const topCountries = countries.slice(0, maxVisible);
  const maxCount = topCountries.length > 0 ? topCountries[0].count : 0;

  const handleCountryClick = (c: GeoCountry) => {
    if (!map) return;

    // Use bbox if available, otherwise fly to lat/lon
    if (c.bbox && c.bbox.length === 4) {
      const bounds: L.LatLngBounds = [
        [c.bbox[0], c.bbox[1]],
        [c.bbox[2], c.bbox[3]],
      ] as any;
      map.flyToBounds(bounds, { padding: [50, 50], duration: 1.2 });
    } else if (c.lat && c.lon) {
      map.flyTo([c.lat, c.lon], c.zoom ?? 4, { duration: 1.2 });
    }
  };

  if (countries.length === 0) {
    return (
      <div className="cyber-card p-4 scanlines">
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 size={14} className="text-cyber-textMuted" />
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">
            Country Breakdown
          </h3>
        </div>
        <div className="flex items-center justify-center h-32 text-cyber-textMuted">
          <div className="text-center">
            <Globe size={32} className="mx-auto mb-2 opacity-30" />
            <p className="text-xs">No geographic data available</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="cyber-card p-4 scanlines">
      {/* Header with summary */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <BarChart3 size={14} className="text-cyber-accent" />
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider">
            Top Countries by Events
          </h3>
          <span className="text-xs text-cyber-textMuted font-mono">
            ({countries.length} regions · {totalEvents.toLocaleString()} events)
          </span>
        </div>
        {topCountries.length > 0 && (
          <div className="flex items-center gap-1.5 text-xs text-cyber-textMuted">
            <TrendingUp size={12} />
            <span>Top: {countryFlag(topCountries[0].code)} {topCountries[0].country}</span>
          </div>
        )}
      </div>

      {/* Bar chart rows */}
      <div className="space-y-2">
        {topCountries.map((c, idx) => {
          const barWidth = maxCount > 0 ? (c.count / maxCount) * 100 : 0;
          const isTop = idx === 0;

          return (
            <button
              key={c.country}
              onClick={() => handleCountryClick(c)}
              className="w-full text-left group focus:outline-none"
              title={`Click to zoom to ${c.country}`}
            >
              <div className={`rounded-md transition-all duration-200 ${
                isTop
                  ? 'bg-cyber-accent/5 border border-cyber-accent/20'
                  : 'hover:bg-cyber-panel/30 border border-transparent'
              }`}>
                <div className="flex items-center gap-2 p-2">
                  {/* Rank */}
                  <span className={`text-xs font-mono w-5 text-right ${
                    isTop ? 'text-cyber-accent font-bold' : 'text-cyber-textMuted'
                  }`}>
                    {idx + 1}
                  </span>

                  {/* Flag + Code */}
                  <span className="text-base leading-none" title={c.country}>
                    {countryFlag(c.code || c.flag)}
                  </span>

                  {/* Country name + Code */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className={`text-xs font-medium truncate ${
                        isTop ? 'text-cyber-text' : 'text-cyber-textMuted group-hover:text-cyber-text'
                      }`}>
                        {c.country}
                      </span>
                      <span className="text-[10px] font-mono text-cyber-textMuted/60 shrink-0">
                        {c.code}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] font-mono text-cyber-textMuted">
                        {c.count.toLocaleString()} events
                      </span>
                      <span className="text-[10px] text-cyber-textMuted/60">·</span>
                      <span className="text-[10px] font-mono text-cyber-accent/80">
                        {c.percentage.toFixed(1)}%
                      </span>
                    </div>
                  </div>

                  {/* Bar */}
                  <div className="w-24 lg:w-32 ml-2 shrink-0">
                    <div className="h-1.5 rounded-full bg-cyber-darker overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500 ease-out"
                        style={{
                          width: `${barWidth}%`,
                          background: `linear-gradient(90deg, ${c.color}, ${c.color}90)`,
                          boxShadow: isTop ? `0 0 6px ${c.color}60` : 'none',
                        }}
                      />
                    </div>
                  </div>

                  {/* Zoom hint icon */}
                  <MapPin size={10} className="text-cyber-textMuted/30 group-hover:text-cyber-accent/60 transition-colors shrink-0" />
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Footer - cumulative stats */}
      <div className="mt-3 pt-3 border-t border-cyber-border/50">
        <div className="flex items-center justify-between text-[10px] text-cyber-textMuted">
          <div className="flex items-center gap-3">
            <span>Top {topCountries.length}: <span className="text-cyber-accent/80 font-mono">
              {topCountries.reduce((s, c) => s + c.count, 0).toLocaleString()} events
            </span></span>
            <span>
              ({topCountries.reduce((s, c) => s + c.percentage, 0).toFixed(1)}% of total)
            </span>
          </div>
          <span className="font-mono">
            {totalEvents.toLocaleString()} total
          </span>
        </div>
      </div>
    </div>
  );
}
