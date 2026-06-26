// ═══════════════════════════════════════════════════
// Color System — single source of truth
// Mirrors tailwind.config.js cyber.* palette
// ═══════════════════════════════════════════════════

// ── Core palette (matches Tailwind cyber.* config) ──
export const CYBER = {
  dark: '#0a0e17',
  darker: '#060a12',
  panel: '#111827',
  panelHover: '#1a2332',
  border: '#1e293b',
  borderLight: '#2d3a4e',
  accent: '#00e5ff',
  accentHover: '#00b8d4',
  pink: '#ff006e',
  purple: '#8338ec',
  green: '#00ff88',
  yellow: '#ffbe0b',
  orange: '#ff7800',
  red: '#ff1744',
  text: '#e2e8f0',
  textMuted: '#64748b',
  textDim: '#3b4a5c',
} as const;

// ── Severity colors (Critical=red, High=orange, Medium=yellow, Low=green) ──
export const SEVERITY = {
  CRITICAL: CYBER.red,
  HIGH: CYBER.orange,
  MEDIUM: CYBER.yellow,
  LOW: CYBER.green,
} as const;

// Severity style helper with bg/glow for badges
type SeverityStyle = { color: string; bg: string; border: string; glow: string };
export function severityStyle(sev: string): SeverityStyle {
  switch (sev) {
    case 'CRITICAL':
    case 'critical':
      return { color: CYBER.red, bg: 'rgba(255,23,68,0.12)', border: CYBER.red, glow: 'rgba(255,23,68,0.4)' };
    case 'HIGH':
    case 'high':
      return { color: CYBER.orange, bg: 'rgba(255,120,0,0.12)', border: CYBER.orange, glow: 'rgba(255,120,0,0.4)' };
    case 'MEDIUM':
    case 'medium':
      return { color: CYBER.yellow, bg: 'rgba(255,190,11,0.12)', border: CYBER.yellow, glow: 'rgba(255,190,11,0.4)' };
    case 'LOW':
    case 'low':
    default:
      return { color: CYBER.green, bg: 'rgba(0,255,136,0.12)', border: CYBER.green, glow: 'rgba(0,255,136,0.4)' };
  }
}

// Severity badge Tailwind class
export function severityBadgeClass(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'cyber-badge-block';
    case 'HIGH': return 'cyber-badge-warning';
    case 'MEDIUM': return 'cyber-badge-info';
    case 'LOW':
    default: return 'cyber-badge-pass';
  }
}

// Severity text class
export function severityTextClass(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'text-cyber-red';
    case 'HIGH': return 'text-cyber-orange';
    case 'MEDIUM': return 'text-cyber-yellow';
    case 'LOW':
    default: return 'text-cyber-green';
  }
}

// ── Network/Category colors ──
export const NETWORK = {
  LAN: CYBER.green,
  WAN: CYBER.pink,
  VPN: CYBER.purple,
  INTERNAL: CYBER.yellow,
  OWN: CYBER.accent,
  DMZ: CYBER.yellow,
  UNKNOWN: CYBER.textMuted,
} as const;

function networkColor(category: string): string {
  return (NETWORK as Record<string, string>)[category] ?? CYBER.textMuted;
}
export { networkColor };

// ── Chart palette (teal/magenta/green/amber/red) ──
export const CHART = {
  teal: '#06b6d4',
  tealFill: 'rgba(6, 182, 212, 0.5)',
  magenta: CYBER.pink,
  green: CYBER.green,
  amber: CYBER.yellow,
  red: CYBER.red,
  cyan: CYBER.accent,
  purple: CYBER.purple,
} as const;

// Chart method colors (sequential palette)
export const METHOD_COLORS = [
  CYBER.green,
  CYBER.accent,
  CYBER.pink,
  CYBER.yellow,
  CYBER.orange,
  CYBER.purple, // 6th method slot
];

// ── Chart theme for uPlot / canvas ──
export const CHART_THEME = {
  bg: '#0d1117',
  grid: 'rgba(148, 163, 184, 0.15)',
  tick: 'rgba(148, 163, 184, 0.3)',
  label: '#94a3b8',
  font: 'Inter, system-ui, monospace',
};

// ── Status / threshold colors ──
export const STATUS = {
  ok: { main: CYBER.green, bg: `rgba(0, 255, 136, 0.1)`, glow: `rgba(0, 255, 136, 0.3)` },
  warning: { main: CYBER.orange, bg: `rgba(255, 120, 0, 0.1)`, glow: `rgba(255, 120, 0, 0.3)` },
  critical: { main: CYBER.red, bg: `rgba(255, 23, 68, 0.1)`, glow: `rgba(255, 23, 68, 0.3)` },
  error: { main: CYBER.textMuted, bg: `rgba(100, 116, 139, 0.1)`, glow: `rgba(100, 116, 139, 0.2)` },
} as const;

function statusColor(status?: string) {
  return (STATUS as Record<string, typeof STATUS.ok>)[status || 'ok'] ?? STATUS.ok;
}
export { statusColor };

// ── Nginx severity colors ──
export const NGINX_SEVERITY = {
  CRITICAL: { bg: `rgba(255, 23, 68, 0.15)`, text: CYBER.red, glow: `rgba(255, 23, 68, 0.6)` },
  HIGH: { bg: `rgba(255, 120, 0, 0.15)`, text: CYBER.orange, glow: `rgba(255, 120, 0, 0.6)` },
  MEDIUM: { bg: `rgba(255, 190, 11, 0.15)`, text: CYBER.yellow, glow: `rgba(255, 190, 11, 0.5)` },
  LOW: { bg: `rgba(0, 255, 136, 0.15)`, text: CYBER.green, glow: `rgba(0, 255, 136, 0.5)` },
};

function nginxSeverityColor(sev: string) {
  return (NGINX_SEVERITY as unknown as Record<string, typeof NGINX_SEVERITY.CRITICAL>)[sev] ?? { bg: CYBER.border, text: CYBER.textMuted, glow: 'transparent' };
}
export { nginxSeverityColor };

// ── Recharts tooltip style ──
export const RECHARTS_TOOLTIP = {
  background: CYBER.darker,
  border: `1px solid ${CYBER.border}`,
  borderRadius: '8px',
  color: CYBER.text,
  fontFamily: 'monospace',
} as const;

// ── Classification colors (Rules ML) ──
export const CLASSIFICATION = {
  GOOD: CYBER.green,
  ABUSIVE: CYBER.red,
  HIGH_TRAFFIC: CYBER.accent,
  LOW_TRAFFIC: CYBER.yellow,
} as const;