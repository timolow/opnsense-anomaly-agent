// ═══════════════════════════════════════════════════
// Geo Tab - Interactive world map visualization
// ═══════════════════════════════════════════════════

import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { api } from '@/api';
import type { GeoData } from '@/types';
import { Globe, Map as MapIcon } from 'lucide-react';

// Fix for Leaflet default marker icons in Vite builds
delete (L.Icon.Default.prototype as Record<string, unknown>)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

// Region-to-coordinate mapping (center points for markers)
const REGION_COORDS: Record<string, [number, number]> = {
  'US': [39.8283, -98.5795],
  'China': [35.8617, 104.1954],
  'Europe/Russia': [55.7558, 37.6173],
  'Japan/Korea': [36.2048, 128.5000],
  'Other': [0, 0],
  'EU': [50.8503, 4.9058],
  'UK': [51.5074, -0.1278],
  'Germany': [51.1657, 10.4515],
  'France': [46.2276, 2.2137],
  'Brazil': [-14.235, -51.9253],
  'India': [20.5937, 78.9629],
  'Australia': [-25.2744, 133.7751],
  'Canada': [56.1304, -106.3468],
  'Russia': [61.5240, 105.3188],
  'Japan': [36.2048, 138.2529],
  'South Korea': [35.9078, 127.7669],
};

// ISO country code to coordinates
const COUNTRY_TO_COORDS: Record<string, [number, number]> = {
  'US': [39.8283, -98.5795],
  'RU': [61.5240, 105.3188],
  'DE': [51.1657, 10.4515],
  'GB': [51.5074, -0.1278],
  'FR': [46.2276, 2.2137],
  'JP': [36.2048, 138.2529],
  'BR': [-14.235, -51.9253],
  'IN': [20.5937, 78.9629],
  'KR': [35.9078, 127.7669],
  'AU': [-25.2744, 133.7751],
  'CA': [56.1304, -106.3468],
  'NL': [52.1326, 5.2913],
  'IT': [41.8719, 12.5674],
  'ES': [40.4637, -3.7492],
  'IR': [32.4279, 53.6880],
  'KP': [40.3399, 127.5101],
  'UA': [48.3794, 31.1656],
  'SE': [60.1282, 18.6435],
  'NO': [60.4720, 8.4689],
  'CN': [35.8617, 104.1954],
};

function getCoords(country: string): [number, number] {
  if (REGION_COORDS[country]) return REGION_COORDS[country];
  if (COUNTRY_TO_COORDS[country]) return COUNTRY_TO_COORDS[country];
  // Extract ISO-like part from compound names (e.g., "Europe/Russia")
  const parts = country.split('/');
  for (const part of parts) {
    if (REGION_COORDS[part]) return REGION_COORDS[part];
    if (COUNTRY_TO_COORDS[part]) return COUNTRY_TO_COORDS[part];
  }
  // Fallback scatter for unknown regions
  const hash = country.split('').reduce((a, ch) => a + ch.charCodeAt(0), 0);
  return [Math.sin(hash) * 25, Math.cos(hash * 1.3) * 40];
}

// ── Leaflet dark-theme CSS overrides ──
const LeafletStyles = () => (
  <style dangerouslySetInnerHTML={{ __html: `
    .leaflet-control-attribution {
      background: rgba(10, 14, 23, 0.85) !important;
      color: #64748b !important;
      backdrop-filter: blur(8px);
    }
    .leaflet-control-attribution a {
      color: #00e5ff !important;
    }
    .leaflet-bar a {
      background: rgba(17, 24, 39, 0.9) !important;
      color: #00e5ff !important;
      border-bottom-color: #1e293b !important;
      backdrop-filter: blur(8px);
    }
    .leaflet-bar a:hover {
      background: rgba(0, 229, 255, 0.15) !important;
      color: #00e5ff !important;
    }
    .leaflet-bar {
      border: 1px solid #1e293b !important;
      border-radius: 8px !important;
      overflow: hidden;
    }
    .leaflet-popup-content-wrapper {
      background: rgba(17, 24, 39, 0.95) !important;
      color: #e2e8f0 !important;
      border: 1px solid #1e293b !important;
      border-radius: 10px !important;
      box-shadow: 0 0 20px rgba(0, 229, 255, 0.15), 0 8px 32px rgba(0, 0, 0, 0.4) !important;
      backdrop-filter: blur(12px);
    }
    .leaflet-popup-tip {
      background: rgba(17, 24, 39, 0.95) !important;
      border: 1px solid #1e293b !important;
    }
    .leaflet-popup-close-button {
      color: #64748b !important;
    }
    .leaflet-popup-close-button:hover {
      color: #00e5ff !important;
    }
    .leaflet-container {
      background: #0a0e17 !important;
    }
    .geo-tooltip {
      background: rgba(17, 24, 39, 0.9) !important;
      border: 1px solid #1e293b !important;
      color: #e2e8f0 !important;
      border-radius: 6px !important;
      padding: 4px 8px !important;
      font-family: 'JetBrains Mono', monospace !important;
      font-size: 11px !important;
      box-shadow: 0 0 10px rgba(0, 229, 255, 0.2) !important;
    }
    .geo-tooltip::before {
      border-top-color: rgba(17, 24, 39, 0.9) !important;
    }
  ` }} />
);

// ── Map component ──
function MapLayer({ data }: { data: GeoData }) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<L.Map | null>(null);
  const markersRef = useRef<L.CircleMarker[]>([]);

  // Initialize map once
  useEffect(() => {
    if (!mapRef.current || mapInstance.current) return;

    const map = L.map(mapRef.current, {
      center: [30, 10] as [number, number],
      zoom: 3,
      minZoom: 2,
      maxZoom: 8,
      zoomControl: false,
      attributionControl: true,
      worldCopyJump: true,
    });

    // CartoDB Dark Matter tiles - no API key needed
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(map);

    // Zoom control top-right
    L.control.zoom({ position: 'topright' }).addTo(map);

    mapInstance.current = map;

    return () => {
      map.remove();
      mapInstance.current = null;
    };
  }, []);

  // Update markers on data change
  useEffect(() => {
    if (!mapInstance.current || !data?.countries?.length) return;

    const map = mapInstance.current;
    const maxCount = Math.max(...data.countries.map(c => c.count));
    const total = data.countries.reduce((s, c) => s + c.count, 0);

    // Clear old markers
    markersRef.current.forEach(m => m.remove());
    markersRef.current = [];

    const bounds: L.LatLngTuple[] = [];

    data.countries
      .filter(c => c.country !== 'Other')
      .sort((a, b) => b.count - a.count)
      .forEach(c => {
        const coords = getCoords(c.country);
        const ratio = maxCount > 0 ? c.count / maxCount : 0;
        const radius = 6 + ratio * 34;

        const circle = L.circleMarker(coords as L.LatLngExpression, {
          radius,
          fillColor: c.color || '#00e5ff',
          color: c.color || '#00e5ff',
          weight: 1.5,
          opacity: 0.9,
          fillOpacity: 0.35,
        }).addTo(map);

        const share = total > 0 ? ((c.count / total) * 100).toFixed(1) : '0.0';

        const popupContent = document.createElement('div');
        popupContent.style.fontFamily = "'JetBrains Mono', monospace";
        popupContent.style.minWidth = '180px';

        const nameDiv = document.createElement('div');
        nameDiv.style.cssText = 'font-size:14px;font-weight:700;margin-bottom:6px;';
        nameDiv.style.color = c.color || '#00e5ff';
        nameDiv.textContent = c.country;
        popupContent.appendChild(nameDiv);

        const row1 = document.createElement('div');
        row1.style.cssText = 'display:flex;justify-content:space-between;margin-bottom:3px;';
        row1.innerHTML = '<span style="color:#64748b;">Events (24h)</span><span style="color:#e2e8f0;">' + c.count.toLocaleString() + '</span>';
        popupContent.appendChild(row1);

        const row2 = document.createElement('div');
        row2.style.cssText = 'display:flex;justify-content:space-between;';
        row2.innerHTML = '<span style="color:#64748b;">Share</span><span style="color:#00e5ff;">' + share + '%</span>';
        popupContent.appendChild(row2);

        circle.bindPopup(popupContent, { maxWidth: 300 });
        circle.bindTooltip(c.country, {
          permanent: false,
          direction: 'top',
          offset: [0, -10],
          className: 'geo-tooltip',
        });

        markersRef.current.push(circle);
        bounds.push(coords);
      });

    if (bounds.length > 1) {
      map.fitBounds(L.latLngBounds(bounds).pad(0.3), { animate: true, duration: 0.8 });
    }
  }, [data]);

  return (
    <div className="relative w-full h-full rounded-xl overflow-hidden border border-cyber-border">
      <div ref={mapRef} className="w-full h-full" />
      <div className="pointer-events-none absolute inset-0 scanlines opacity-10" style={{ zIndex: 1000 }} />
    </div>
  );
}

// ── Stats Bar ──
function GeoStats({ countries }: { countries: Array<{ country: string; count: number; color: string }> }) {
  const total = countries.reduce((s, c) => s + c.count, 0);
  const top = countries[0];
  const unique = countries.length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
      {[
        { label: 'Total Events', value: total.toLocaleString(), icon: Globe },
        { label: 'Top Source', value: top?.country || '\u2014', icon: MapIcon },
        { label: 'Top Count', value: top?.count.toLocaleString() || '0', icon: Globe },
        { label: 'Unique Regions', value: unique.toString(), icon: MapIcon },
      ].map(({ label, value, icon: Icon }) => (
        <div key={label} className="cyber-card p-3 scanlines">
          <div className="flex items-center gap-2 mb-1">
            <Icon size={14} className="text-cyber-textMuted" />
            <span className="text-xs text-cyber-textMuted uppercase tracking-wider">{label}</span>
          </div>
          <div className="text-lg font-bold font-mono truncate" style={{ color: '#e2e8f0' }}>{value}</div>
        </div>
      ))}
    </div>
  );
}

// ── Top Sources sidebar ──
function TopSources({ countries }: { countries: Array<{ country: string; count: number; color: string }> }) {
  const total = countries.reduce((s, c) => s + c.count, 0);
  const topCountries = countries.slice(0, 15);

  return (
    <div className="cyber-card p-4 scanlines h-full overflow-y-auto">
      <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4 flex items-center gap-2">
        <Globe size={14} className="text-cyber-accent" />
        Top Sources
      </h3>
      <div className="space-y-2">
        {topCountries.map((c, i) => {
          const pct = total > 0 ? (c.count / total) * 100 : 0;
          return (
            <div key={c.country} className="flex items-center gap-3">
              <span className="text-xs font-mono text-cyber-textDim w-4 text-right">{i + 1}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium truncate" title={c.country}>{c.country}</span>
                  <span className="text-xs font-mono text-cyber-textMuted ml-2">{c.count.toLocaleString()}</span>
                </div>
                <div className="cyber-progress-track h-1.5">
                  <div
                    className="cyber-progress-fill h-1.5 rounded-full transition-all"
                    style={{
                      width: `${pct}%`,
                      background: `linear-gradient(90deg, ${c.color}, ${c.color}80)`,
                      boxShadow: `0 0 6px ${c.color}40`,
                    }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Tab ──
export default function GeoTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<GeoData>({
    queryKey: ['geo'],
    queryFn: api.geo,
    refetchInterval: 60000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center animate-pulse">
            <Globe size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Geographic Distribution</h2>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="cyber-card p-3 animate-pulse h-20 bg-cyber-panel/50" />
          ))}
        </div>
        <div className="cyber-card animate-pulse h-96 bg-cyber-panel/50 rounded-xl" />
      </div>
    );
  }

  if (isError && error) {
    return (
      <div className="cyber-card p-8 text-center">
        <Globe size={32} className="mx-auto text-cyber-red mb-3" />
        <h3 className="text-lg font-bold text-cyber-red mb-2">Failed to load geographic data</h3>
        <p className="text-sm text-cyber-textMuted mb-4">{error.message}</p>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent hover:bg-cyber-accent/20 transition-all"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data?.countries?.length) {
    return (
      <div className="cyber-card p-8 text-center">
        <Globe size={32} className="mx-auto text-cyber-textMuted mb-3" />
        <h3 className="text-lg font-bold mb-2">No geographic data</h3>
        <p className="text-sm text-cyber-textMuted">No country-level event data available yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 h-full flex flex-col">
      <LeafletStyles />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <Globe size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Geographic Distribution</h2>
          <span className="text-xs text-cyber-textMuted font-mono">
            {data.countries.reduce((s, c) => s + c.count, 0).toLocaleString()} total events
          </span>
        </div>
      </div>

      {/* Stats */}
      <GeoStats countries={data.countries} />

      {/* Map + sidebar layout */}
      <div className="flex flex-col lg:flex-row gap-4 flex-1 min-h-0">
        {/* Map container */}
        <div className="flex-1 min-h-[400px] lg:min-h-0 relative">
          <MapLayer data={data} />
        </div>

        {/* Sidebar */}
        <div className="w-full lg:w-72 xl:w-80 shrink-0">
          <TopSources countries={data.countries} />
        </div>
      </div>
    </div>
  );
}
