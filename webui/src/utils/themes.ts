// ═══════════════════════════════════════════════════
// Theme definitions — 5 color palettes
// Each theme maps to CSS custom properties applied
// via [data-theme="..."] on <html>.
// ═══════════════════════════════════════════════════

export type ThemeName = 'cyberpunk' | 'ocean' | 'sunset' | 'matrix' | 'arctic';

interface ThemeDef {
  name: string;
  id: ThemeName;
  // Core colors
  bg: string;
  bgDarker: string;
  panel: string;
  panelHover: string;
  border: string;
  borderLight: string;
  // Text
  text: string;
  textMuted: string;
  textDim: string;
  // Accent
  accent: string;
  accentHover: string;
  secondary: string;
  // Semantic
  green: string;
  yellow: string;
  orange: string;
  red: string;
  // Decorative
  scrollbarTrack: string;
  scrollbarThumb: string;
  scrollbarThumbHover: string;
  // Swatch preview (first 3 colors for the swatch)
  swatch: [string, string, string];
}

export const THEMES: Record<ThemeName, ThemeDef> = {
  cyberpunk: {
    name: 'Cyberpunk',
    id: 'cyberpunk',
    bg: '#0a0e17',
    bgDarker: '#060a12',
    panel: '#111827',
    panelHover: '#1a2332',
    border: '#1e293b',
    borderLight: '#2d3a4e',
    text: '#e2e8f0',
    textMuted: '#64748b',
    textDim: '#3b4a5c',
    accent: '#00e5ff',
    accentHover: '#00b8d4',
    secondary: '#ff006e',
    green: '#00ff88',
    yellow: '#ffbe0b',
    orange: '#ff7800',
    red: '#ff1744',
    scrollbarTrack: '#0d1117',
    scrollbarThumb: '#1e293b',
    scrollbarThumbHover: '#2d3a4e',
    swatch: ['#00e5ff', '#ff006e', '#00ff88'],
  },
  ocean: {
    name: 'Ocean',
    id: 'ocean',
    bg: '#0c2461',
    bgDarker: '#081845',
    panel: '#102a6e',
    panelHover: '#163078',
    border: '#1a3a7a',
    borderLight: '#244a8a',
    text: '#ffffff',
    textMuted: '#88a4c8',
    textDim: '#5577a0',
    accent: '#0abde3',
    accentHover: '#0897b5',
    secondary: '#48dbfb',
    green: '#00d2d3',
    yellow: '#feca57',
    orange: '#ff9f43',
    red: '#ff6b6b',
    scrollbarTrack: '#081845',
    scrollbarThumb: '#1a3a7a',
    scrollbarThumbHover: '#244a8a',
    swatch: ['#0abde3', '#48dbfb', '#00d2d3'],
  },
  sunset: {
    name: 'Sunset',
    id: 'sunset',
    bg: '#2c003e',
    bgDarker: '#1e0028',
    panel: '#3d0a52',
    panelHover: '#4a0e60',
    border: '#5a1870',
    borderLight: '#6a2080',
    text: '#f8e8ff',
    textMuted: '#b088c8',
    textDim: '#7a55a0',
    accent: '#ff9f43',
    accentHover: '#e88a30',
    secondary: '#feca57',
    green: '#55efc4',
    yellow: '#feca57',
    orange: '#ff9f43',
    red: '#ff6348',
    scrollbarTrack: '#1e0028',
    scrollbarThumb: '#5a1870',
    scrollbarThumbHover: '#6a2080',
    swatch: ['#ff9f43', '#feca57', '#ff6348'],
  },
  matrix: {
    name: 'Matrix',
    id: 'matrix',
    bg: '#0a0a0a',
    bgDarker: '#050505',
    panel: '#0f1a0f',
    panelHover: '#142014',
    border: '#1a3b1a',
    borderLight: '#245024',
    text: '#00ff41',
    textMuted: '#003b00',
    textDim: '#002000',
    accent: '#00ff41',
    accentHover: '#00cc33',
    secondary: '#00cc33',
    green: '#00ff41',
    yellow: '#aaff00',
    orange: '#ffaa00',
    red: '#ff3333',
    scrollbarTrack: '#050505',
    scrollbarThumb: '#1a3b1a',
    scrollbarThumbHover: '#245024',
    swatch: ['#00ff41', '#00cc33', '#aaff00'],
  },
  arctic: {
    name: 'Arctic',
    id: 'arctic',
    bg: '#1e272e',
    bgDarker: '#161d22',
    panel: '#253039',
    panelHover: '#2d3a44',
    border: '#354450',
    borderLight: '#445666',
    text: '#dfe6e9',
    textMuted: '#8899a6',
    textDim: '#556677',
    accent: '#74b9ff',
    accentHover: '#5a9ae0',
    secondary: '#a4c8ff',
    green: '#55efc4',
    yellow: '#ffeaa7',
    orange: '#fab1a0',
    red: '#ff7675',
    scrollbarTrack: '#161d22',
    scrollbarThumb: '#354450',
    scrollbarThumbHover: '#445666',
    swatch: ['#74b9ff', '#a4c8ff', '#55efc4'],
  },
};

export const THEME_LIST: ThemeDef[] = Object.values(THEMES);

export const DEFAULT_THEME: ThemeName = 'cyberpunk';

export const STORAGE_KEY = 'dashboard-theme';

export function getStoredTheme(): ThemeName | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored && stored in THEMES) return stored as ThemeName;
  } catch { /* localStorage unavailable */ }
  return null;
}

export function getActiveTheme(): ThemeName {
  return getStoredTheme() ?? DEFAULT_THEME;
}
