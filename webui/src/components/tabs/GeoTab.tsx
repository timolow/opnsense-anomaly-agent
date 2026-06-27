// ═══════════════════════════════════════════════════
// Geo Tab - Interactive geographic map with hotspot markers & heatmap overlay
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useMemo, useCallback, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { GeoData, GeoHotspot } from '@/types';
import { useStore, timeRanges, type TimeRange } from '@/store';
import { Globe, MapPin, AlertTriangle, ExternalLink, X, SlidersHorizontal, Map as MapIcon, Layers } from 'lucide-react';
import * as L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { SEVERITY, CYBER } from '@/utils/colors';

const FLAG_MAP: Record<string, string> = {
  'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪', 'GB': '🇬🇧',
  'FR': '🇫🇷', 'JP': '🇯🇵', 'BR': '🇧🇷', 'IN': '🇮🇳', 'KR': '🇰🇷',
  'AU': '🇦🇺', 'CA': '🇨🇦', 'NL': '🇳🇱', 'IT': '🇮🇹', 'ES': '🇪🇸',
  'IR': '🇮🇷', 'KP': '🇰🇵', 'UA': '🇺🇦', 'SE': '🇸🇪', 'NO': '🇳🇴',
  'EU': '🇪🇺', 'OTHER': '🌐',
};

import { GeoSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';
import { GeoDataPanel } from './GeoDataPanel';

// Fix default marker icons in React
import markerIcon2x from 'leaflet/dist/images/marker-icon-2x.png';
import markerIcon from 'leaflet/dist/images/marker-icon.png';
import markerShadow from 'leaflet/dist/images/marker-shadow.png';

delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

// Severity color mapping
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: SEVERITY.CRITICAL,
  HIGH: SEVERITY.HIGH,
  MEDIUM: SEVERITY.MEDIUM,
  LOW: SEVERITY.LOW,
};

// Calculate marker radius based on event count (logarithmic scale)
function markerRadius(count: number): number {
  if (count <= 0) return 5;
  const minR = 6;
  const maxR = 40;
  const logMin = Math.log10(1);
  const logMax = Math.log10(50000);
  const logVal = Math.log10(Math.max(count, 1));
  return minR + ((logVal - logMin) / (logMax - logMin)) * (maxR - minR);
}

// Country code to flag emoji
function countryFlag(code: string): string {
  return FLAG_MAP[code] || '🌐';
}

// ─────────────────────────────────────────────
// GeoHeatmapLayer — Canvas-based heatmap overlay
// ─────────────────────────────────────────────
// Renders radial gradients (teal→pink) at each hotspot position.
// Supports world-wrap for hotspots near the map edges.

class GeoHeatmapLayer extends L.Layer {
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private pane: HTMLElement | null = null;
  private map: L.Map | null = null;
  private _hotspots: GeoHotspot[] = [];
  private _radius: number = 100;
  private _intensity: number = 0.6;
  private _animFrame: number = 0;

  // Teal (#00e5ff) → Pink (#ff006e) interpolation
  private heatColor(t: number): [number, number, number] {
    const r = Math.round(0 + t * 255);
    const g = Math.round(229 * (1 - t));
    const b = Math.round(255 * (1 - t) + 110 * t);
    return [r, g, b];
  }

  onAdd(map: L.Map): this {
    this.map = map;

    const pane = map.createPane('heatmapPane');
    pane.style.zIndex = '650';
    pane.style.pointerEvents = 'none';
    this.pane = pane;

    const canvas = document.createElement('canvas');
    canvas.style.position = 'absolute';
    canvas.style.left = '0';
    canvas.style.top = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.transition = 'opacity 0.3s ease';
    pane.appendChild(canvas);
    this.canvas = canvas;

    this.ctx = canvas.getContext('2d', { alpha: true });

    map.on('moveend zoomend resize', this._redraw, this);
    this._redraw();

    return this;
  }

  onRemove(map: L.Map): void {
    map.off('moveend zoomend resize', this._redraw, this);
    if (this._animFrame) cancelAnimationFrame(this._animFrame);
    if (this.pane && this.canvas) {
      this.pane.removeChild(this.canvas);
    }
    this.canvas = null;
    this.ctx = null;
    this.pane = null;
    this.map = null;
  }

  // Public API: update data / radius / intensity
  update(hotspots: GeoHotspot[], radius: number, intensity: number): void {
    this._hotspots = hotspots;
    this._radius = radius;
    this._intensity = intensity;
    this._redraw();
  }

  setOpacity(opacity: number): void {
    if (this.canvas) {
      this.canvas.style.opacity = String(opacity);
    }
  }

  private _redraw = (): void => {
    const map = this.map;
    const canvas = this.canvas;
    const ctx = this.ctx;
    if (!map || !canvas || !ctx) return;

    const size = map.getSize();
    canvas.width = size.x;
    canvas.height = size.y;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const hotspots = this._hotspots;
    if (hotspots.length === 0) return;

    // Find max count for normalization
    const maxCount = Math.max(...hotspots.map(h => h.count), 1);

    // Sort by count (draw low-density first so high-density overlays)
    const sorted = [...hotspots].sort((a, b) => a.count - b.count);

    // World width in pixels (for wrapping)
    const worldPx = size.x;

    ctx.globalCompositeOperation = 'lighter';

    for (const h of sorted) {
      // Normalize count → [0, 1] → color
      const t = h.count / maxCount;
      const [r, g, b] = this.heatColor(t);
      const alpha = this._intensity;

      // Draw at primary position and wrapped copies
      const center = map.latLngToContainerPoint([h.lat, h.lon]);

      // Draw up to 3 copies to handle wrapping at map edges
      for (let i = -1; i <= 1; i++) {
        const px = center.x + i * worldPx;

        // Skip if entirely outside viewport
        if (px + this._radius < 0 || px - this._radius > canvas.width) continue;
        if (center.y + this._radius < 0 || center.y - this._radius > canvas.height) continue;

        const gradient = ctx.createRadialGradient(px, center.y, 0, px, center.y, this._radius);
        gradient.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${alpha})`);
        gradient.addColorStop(0.4, `rgba(${r}, ${g}, ${b}, ${alpha * 0.5})`);
        gradient.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);

        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(px, center.y, this._radius, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    ctx.globalCompositeOperation = 'source-over';
  };
}

// View mode type
type GeoViewMode = 'markers' | 'heatmap' | 'both';

// ─────────────────────────────────────────────
// GeoMap component — Leaflet map + markers + heatmap layer
// ─────────────────────────────────────────────
// Expose: zoomTo(latLng, zoom), flyToBbox(bbox, zoom)
function GeoMap({
  hotspots,
  onHotspotClick,
  viewMode,
  heatmapRadius,
  heatmapIntensity,
  onRef,
}: {
  hotspots: GeoHotspot[];
  onHotspotClick: (h: GeoHotspot) => void;
  viewMode: GeoViewMode;
  heatmapRadius: number;
  heatmapIntensity: number;
  onRef?: (map: L.Map | null) => void;
}) {
  const containersRef = useRef<HTMLDivElement>(null);
  const circlesRef = useRef<L.CircleMarker[]>([]);
  const pulseCirclesRef = useRef<L.CircleMarker[]>([]);
  const pulseIntervalsRef = useRef<ReturnType<typeof setInterval>[]>([]);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const heatmapRef = useRef<GeoHeatmapLayer | null>(null);
  const prevViewModeRef = useRef<GeoViewMode>('markers');

  // Initialize map
  useEffect(() => {
    if (!containersRef.current || mapInstanceRef.current) return;

    const map = L.map(containersRef.current, {
      center: [30, 10] as [number, number],
      zoom: 2,
      minZoom: 2,
      maxZoom: 10,
      zoomControl: true,
      attributionControl: true,
      worldCopyJump: true,
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 20,
    }).addTo(map);

    mapInstanceRef.current = map;
    onRef?.(map);

    return () => {
      map.remove();
      mapInstanceRef.current = null;
      onRef?.(null);
    };
  }, []);

  // Manage heatmap layer creation/destruction
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    const needsHeatmap = viewMode === 'heatmap' || viewMode === 'both';
    const hadHeatmap = heatmapRef.current !== null;

    if (needsHeatmap && !hadHeatmap) {
      const layer = new GeoHeatmapLayer();
      layer.addTo(map);
      layer.update(hotspots, heatmapRadius, heatmapIntensity);
      // Animate in
      layer.setOpacity(0);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          layer.setOpacity(1);
        });
      });
      heatmapRef.current = layer;
    } else if (!needsHeatmap && hadHeatmap) {
      // Animate out, then remove
      const layer = heatmapRef.current!;
      layer.setOpacity(0);
      setTimeout(() => {
        if (heatmapRef.current === layer) {
          layer.remove();
          heatmapRef.current = null;
        }
      }, 350);
    }

    prevViewModeRef.current = viewMode;
  }, [viewMode]);

  // Update heatmap layer data when hotspots/radius/intensity change
  useEffect(() => {
    if (heatmapRef.current) {
      heatmapRef.current.update(hotspots, heatmapRadius, heatmapIntensity);
    }
  }, [hotspots, heatmapRadius, heatmapIntensity]);

  // Update heatmap layer opacity when switching between heatmap/both
  useEffect(() => {
    if (!heatmapRef.current) return;
    // Both modes: heatmap always visible when layer exists
    heatmapRef.current.setOpacity(1);
  }, [viewMode]);

  // Update markers when hotspots change
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    // Show/hide markers based on view mode
    const showMarkers = viewMode === 'markers' || viewMode === 'both';
    const markerOpacity = viewMode === 'both' ? 0.5 : 0.9;
    const markerFillOpacity = viewMode === 'both' ? 0.2 : 0.35;

    // Remove old markers and cleanup
    circlesRef.current.forEach(c => {
      if ((c as any)._pulseInterval) {
        clearInterval((c as any)._pulseInterval);
        (c as any)._pulseCircle?.remove();
      }
      c.remove();
    });
    pulseCirclesRef.current.forEach(c => c.remove());
    pulseIntervalsRef.current.forEach(id => clearInterval(id));
    circlesRef.current = [];
    pulseCirclesRef.current = [];
    pulseIntervalsRef.current = [];

    if (!showMarkers) return;

    hotspots.forEach(h => {
      const color = SEVERITY_COLORS[h.severity] || SEVERITY.LOW;
      const radius = markerRadius(h.count);

      const circle = L.circleMarker([h.lat, h.lon], {
        radius,
        fillColor: color,
        color: color,
        weight: 2,
        opacity: markerOpacity,
        fillOpacity: markerFillOpacity,
        bubblingMouseEvents: false,
      }).addTo(map);

      // Pulsing effect for critical/high
      if (h.severity === 'CRITICAL' || h.severity === 'HIGH') {
        const pulseCircle = L.circleMarker([h.lat, h.lon], {
          radius: radius * 1.5,
          fillColor: color,
          color: color,
          weight: 1,
          opacity: 0,
          fillOpacity: 0,
          bubblingMouseEvents: false,
        }).addTo(map);

        pulseCirclesRef.current.push(pulseCircle);

        let pulseOpacity = 0;
        let growing = true;
        const interval = setInterval(() => {
          pulseOpacity += growing ? 0.02 : -0.02;
          if (pulseOpacity >= 0.15) growing = false;
          if (pulseOpacity <= 0) growing = true;
          pulseCircle.setStyle({
            opacity: pulseOpacity,
            fillOpacity: pulseOpacity * 0.5,
          });
        }, 50);

        (circle as any)._pulseInterval = interval;
        (circle as any)._pulseCircle = pulseCircle;
        pulseIntervalsRef.current.push(interval);
      }

      circle.on('mouseover', () => {
        circle.setStyle({
          fillOpacity: viewMode === 'both' ? 0.4 : 0.6,
          weight: 3,
          opacity: 1,
        });
      });

      circle.on('mouseout', () => {
        circle.setStyle({
          fillOpacity: markerFillOpacity,
          weight: 2,
          opacity: markerOpacity,
        });
      });

      circle.on('click', () => {
        onHotspotClick(h);
        map.flyTo([h.lat, h.lon], Math.max(map.getZoom(), 5), { duration: 1 });
      });

      circlesRef.current.push(circle);
    });

    // Fit bounds if we have hotspots
    if (hotspots.length > 0 && showMarkers) {
      const group = L.featureGroup(circlesRef.current);
      map.flyToBounds(group.getBounds().pad(0.3), { duration: 1.5 });
    }

    // Cleanup on unmount
    return () => {
      circlesRef.current.forEach(c => {
        if ((c as any)._pulseInterval) {
          clearInterval((c as any)._pulseInterval);
          (c as any)._pulseCircle?.remove();
        }
        c.remove();
      });
      pulseCirclesRef.current.forEach(c => c.remove());
      pulseIntervalsRef.current.forEach(id => clearInterval(id));
      circlesRef.current = [];
      pulseCirclesRef.current = [];
      pulseIntervalsRef.current = [];
    };
  }, [hotspots, onHotspotClick, viewMode]);

  return <div ref={containersRef} className="w-full h-full rounded-lg overflow-hidden" />;
}

// Severity filter option type
type SeverityFilter = '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

// ─────────────────────────────────────────────
// GeoTab — Main component with controls
// ─────────────────────────────────────────────
export default function GeoTab() {
  const timeRange = useStore(s => s.timeRange);
  const hours = timeRanges[timeRange as TimeRange]?.hours ?? 24;

const { data, isLoading, isError, error, refetch } = useQuery<GeoData>({
    queryKey: ['geo', hours],
    queryFn: () => api.geo(),
    refetchInterval: 60000,
  });

  // Severity filter state
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('');
  const [selectedHotspot, setSelectedHotspot] = useState<GeoHotspot | null>(null);
  const [showSidebar, setShowSidebar] = useState(true);

  // Heatmap state
  const [viewMode, setViewMode] = useState<GeoViewMode>('markers');
  const [heatmapRadius, setHeatmapRadius] = useState(120);
  const [heatmapIntensity, setHeatmapIntensity] = useState(0.6);
  const [showControls, setShowControls] = useState(false);

  // Map ref — shared with GeoDataPanel for zoom-to-country
  const mapRef = useRef<L.Map | null>(null);
  const handleMapRef = useCallback((m: L.Map | null) => {
    mapRef.current = m;
  }, []);

  const hotspots = data?.hotspots || [];
  const countries = data?.countries || [];
  const totalEvents = data?.total_events ?? countries.reduce((s, c) => s + c.count, 0);

  // Filtered hotspots
  const filteredHotspots = useMemo(() => {
    if (!severityFilter) return hotspots;
    return hotspots.filter(h => h.severity === severityFilter);
  }, [hotspots, severityFilter]);

  // Stats
  const severityStats = useMemo(() => {
    const stats = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    hotspots.forEach(h => {
      stats[h.severity] = (stats[h.severity] || 0) + 1;
    });
    return stats;
  }, [hotspots]);

  const handleHotspotClick = useCallback((h: GeoHotspot) => {
    setSelectedHotspot(h);
  }, []);

  if (isLoading) return <GeoSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Geography" />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
            <Globe size={16} className="text-cyber-accent" />
          </div>
          <h2 className="text-lg font-bold">Geographic Distribution</h2>
          <span className="text-xs text-cyber-textMuted font-mono">
            {totalEvents.toLocaleString()} total events · {hotspots.length} sources
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* View mode toggle */}
          <div className="flex items-center bg-cyber-darker border border-cyber-border rounded-lg overflow-hidden">
            {(['markers', 'heatmap', 'both'] as GeoViewMode[]).map(mode => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`px-3 py-1.5 text-xs font-medium transition-all flex items-center gap-1.5 ${
                  viewMode === mode
                    ? 'bg-cyber-accent/20 text-cyber-accent border-r border-cyber-border last:border-r-0'
                    : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panel/50 border-r border-cyber-border last:border-r-0'
                }`}
                title={mode === 'markers' ? 'Show markers only' : mode === 'heatmap' ? 'Show heatmap only' : 'Show both'}
              >
                {mode === 'markers' && <MapIcon size={12} />}
                {mode === 'heatmap' && <Layers size={12} />}
                {mode === 'both' && <Layers size={12} />}
                <span className="hidden sm:inline capitalize">{mode}</span>
              </button>
            ))}
          </div>
          <button
            onClick={() => setShowSidebar(!showSidebar)}
            className="text-xs px-2 py-1 rounded border border-cyber-border text-cyber-textMuted hover:text-cyber-text hover:border-cyber-accent transition-all"
          >
            {showSidebar ? 'Hide' : 'Show'} Details
          </button>
        </div>
      </div>

      <div className={`grid gap-4 ${showSidebar ? 'grid-cols-1 lg:grid-cols-4' : 'grid-cols-1'}`}>
        {/* Map area */}
        <div className={`${showSidebar ? 'lg:col-span-3' : 'col-span-1'} cyber-card scanlines overflow-hidden`} style={{ minHeight: '500px' }}>
          <div className="h-[500px] lg:h-[600px] xl:h-[700px] relative">
            {filteredHotspots.length > 0 ? (
              <GeoMap
                hotspots={filteredHotspots}
                onHotspotClick={handleHotspotClick}
                viewMode={viewMode}
                heatmapRadius={heatmapRadius}
                heatmapIntensity={heatmapIntensity}
                onRef={handleMapRef}
              />
            ) : (
              <div className="flex items-center justify-center h-full text-cyber-textMuted">
                <div className="text-center">
                  <Globe size={48} className="mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No hotspot data for this filter</p>
                  {severityFilter && (
                    <button
                      onClick={() => setSeverityFilter('')}
                      className="mt-2 text-xs text-cyber-accent hover:underline"
                    >
                      Clear filter
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* Heatmap controls overlay */}
            {(viewMode === 'heatmap' || viewMode === 'both') && (
              <div className="absolute top-4 right-4 z-[1000]">
                <button
                  onClick={() => setShowControls(!showControls)}
                  className="bg-cyber-darker/90 backdrop-blur-sm rounded-lg p-2 border border-cyber-border hover:border-cyber-accent transition-all text-cyber-textMuted hover:text-cyber-accent"
                  title="Heatmap settings"
                >
                  <SlidersHorizontal size={16} />
                </button>
                {showControls && (
                  <div className="absolute top-0 right-0 mt-2 bg-cyber-darker/95 backdrop-blur-sm rounded-lg p-4 border border-cyber-border w-56 z-[1001]">
                    <div className="space-y-3">
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <label className="text-xs text-cyber-textMuted font-mono">Radius</label>
                          <span className="text-xs text-cyber-accent font-mono">{heatmapRadius}px</span>
                        </div>
                        <input
                          type="range"
                          min="50"
                          max="300"
                          step="10"
                          value={heatmapRadius}
                          onChange={e => setHeatmapRadius(Number(e.target.value))}
                          className="w-full accent-cyber-accent"
                        />
                      </div>
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <label className="text-xs text-cyber-textMuted font-mono">Intensity</label>
                          <span className="text-xs text-cyber-accent font-mono">{heatmapIntensity.toFixed(1)}</span>
                        </div>
                        <input
                          type="range"
                          min="0.1"
                          max="1.0"
                          step="0.1"
                          value={heatmapIntensity}
                          onChange={e => setHeatmapIntensity(Number(e.target.value))}
                          className="w-full accent-cyber-accent"
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Severity legend overlay */}
            {(viewMode === 'markers' || viewMode === 'both') && (
              <div className="absolute bottom-4 left-4 bg-cyber-darker/90 backdrop-blur-sm rounded-lg p-3 border border-cyber-border z-[1000]">
                <div className="text-xs font-semibold text-cyber-textMuted uppercase tracking-wider mb-2">Severity</div>
                <div className="space-y-1">
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                    <div key={sev} className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                      <span className="text-xs text-cyber-text">{sev}</span>
                      <span className="text-xs text-cyber-textMuted font-mono">({severityStats[sev]})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Heatmap density legend overlay */}
            {(viewMode === 'heatmap' || viewMode === 'both') && (
              <div className="absolute bottom-4 left-4 bg-cyber-darker/90 backdrop-blur-sm rounded-lg p-3 border border-cyber-border z-[1000]">
                <div className="text-xs font-semibold text-cyber-textMuted uppercase tracking-wider mb-2">Event Density</div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-cyber-textMuted font-mono">Low</span>
                  <div
                    className="h-3 w-32 rounded-full"
                    style={{
                      background: `linear-gradient(90deg, ${CYBER.accent}, ${CYBER.pink})`,
                    }}
                  />
                  <span className="text-[10px] text-cyber-textMuted font-mono">High</span>
                </div>
                <div className="mt-1.5 flex items-center justify-between text-[10px] text-cyber-textMuted font-mono">
                  <span>Radius: {heatmapRadius}px</span>
                  <span>Intensity: {heatmapIntensity.toFixed(1)}</span>
                </div>
              </div>
            )}

            {/* Active filter indicator */}
            {severityFilter && (
              <div className="absolute top-4 left-4 bg-cyber-darker/90 backdrop-blur-sm rounded-lg px-3 py-2 border border-cyber-accent/30 z-[1000] flex items-center gap-2">
                <span className="text-xs text-cyber-accent font-medium">Filter: {severityFilter}</span>
                <button
                  onClick={() => setSeverityFilter('')}
                  className="text-cyber-textMuted hover:text-cyber-text"
                >
                  <X size={14} />
                </button>
              </div>
            )}

            {/* Active view mode indicator */}
            {viewMode !== 'markers' && (
              <div className="absolute top-4 left-4 bg-cyber-darker/90 backdrop-blur-sm rounded-lg px-3 py-2 border border-cyber-accent/30 z-[1000] flex items-center gap-2">
                <Layers size={14} className="text-cyber-accent" />
                <span className="text-xs text-cyber-accent font-medium capitalize">{viewMode} view</span>
                <button
                  onClick={() => setViewMode('markers')}
                  className="text-cyber-textMuted hover:text-cyber-text"
                >
                  <X size={14} />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Sidebar - Details panel */}
        {showSidebar && (
          <div className="lg:col-span-1 space-y-4">
            {/* Severity filter */}
            <div className="cyber-card p-4 scanlines">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3">
                Filter by Severity
              </h3>
              <div className="space-y-1">
                <button
                  onClick={() => setSeverityFilter('')}
                  className={`w-full text-left px-3 py-2 rounded text-xs font-medium transition-all ${
                    !severityFilter
                      ? 'bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30'
                      : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panel/50 border border-transparent'
                  }`}
                >
                  All ({hotspots.length})
                </button>
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
                    className={`w-full text-left px-3 py-2 rounded text-xs font-medium transition-all flex items-center gap-2 ${
                      severityFilter === sev
                        ? 'border border-current'
                        : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panel/50 border border-transparent'
                    }`}
                    style={severityFilter === sev ? { color: SEVERITY_COLORS[sev], borderColor: SEVERITY_COLORS[sev] + '40' } : {}}
                  >
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                    <span>{sev}</span>
                    <span className="ml-auto font-mono opacity-60">{severityStats[sev]}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Selected hotspot detail */}
            {selectedHotspot && (
              <div className="cyber-card p-4 scanlines">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider flex items-center gap-2">
                    <MapPin size={14} /> Source Detail
                  </h3>
                  <button
                    onClick={() => setSelectedHotspot(null)}
                    className="text-cyber-textMuted hover:text-cyber-text"
                  >
                    <X size={14} />
                  </button>
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Source IP</span>
                    <span className="font-mono text-cyber-text">{selectedHotspot.src_ip}</span>
                  </div>
                  {selectedHotspot.dst_ip && (
                    <div className="flex justify-between">
                      <span className="text-cyber-textMuted">Top Dest</span>
                      <span className="font-mono text-cyber-text">{selectedHotspot.dst_ip}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Country</span>
                    <span className="text-cyber-text">{countryFlag(selectedHotspot.country)} {selectedHotspot.country_name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Events</span>
                    <span className="font-mono text-cyber-text">{selectedHotspot.count.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Unique Dests</span>
                    <span className="font-mono text-cyber-text">{selectedHotspot.unique_dst}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Severity</span>
                    <span
                      className="font-medium px-2 py-0.5 rounded"
                      style={{
                        color: SEVERITY_COLORS[selectedHotspot.severity],
                        background: `${SEVERITY_COLORS[selectedHotspot.severity]}18`,
                        border: `1px solid ${SEVERITY_COLORS[selectedHotspot.severity]}30`,
                      }}
                    >
                      {selectedHotspot.severity}
                    </span>
                  </div>
                  {selectedHotspot.interface && (
                    <div className="flex justify-between">
                      <span className="text-cyber-textMuted">Interface</span>
                      <span className="font-mono text-cyber-text">{selectedHotspot.interface}</span>
                    </div>
                  )}
                  {selectedHotspot.action && (
                    <div className="flex justify-between">
                      <span className="text-cyber-textMuted">Action</span>
                      <span className="font-mono text-cyber-text uppercase">{selectedHotspot.action}</span>
                    </div>
                  )}
                  {selectedHotspot.attack_type && (
                    <div className="flex justify-between">
                      <span className="text-cyber-textMuted">Threat</span>
                      <span className="font-mono text-cyber-orange">{selectedHotspot.attack_type}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-cyber-textMuted">Coords</span>
                    <span className="font-mono text-cyber-textMuted">{selectedHotspot.lat.toFixed(2)}, {selectedHotspot.lon.toFixed(2)}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Top sources list */}
            <div className="cyber-card p-4 scanlines">
              <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-3 flex items-center gap-2">
                <AlertTriangle size={14} /> Top Sources
              </h3>
              <div className="space-y-2">
                {filteredHotspots.slice(0, 10).map((h, i) => (
                  <button
                    key={h.ip}
                    onClick={() => setSelectedHotspot(h)}
                    className={`w-full text-left cyber-card p-2 rounded cursor-pointer transition-all hover:border-cyber-accent/50 ${
                      selectedHotspot?.ip === h.ip ? 'border-cyber-accent/50' : ''
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-cyber-textMuted font-mono w-4">{i + 1}</span>
                      <span className="text-sm">{countryFlag(h.country)}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-mono truncate text-cyber-text">{h.src_ip}</div>
                        <div className="text-xs text-cyber-textMuted">{h.count.toLocaleString()} events</div>
                      </div>
                      <span
                        className="text-xs font-medium px-1.5 py-0.5 rounded"
                        style={{
                          color: SEVERITY_COLORS[h.severity],
                          background: `${SEVERITY_COLORS[h.severity]}15`,
                        }}
                      >
                        {h.severity.charAt(0)}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Geographic data panel with bar chart */}
      <GeoDataPanel
        countries={countries}
        totalEvents={totalEvents}
        map={mapRef.current}
      />
    </div>
  );
}
