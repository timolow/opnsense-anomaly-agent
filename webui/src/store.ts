// ═══════════════════════════════════════════════════
// Store - Zustand state management
// ═══════════════════════════════════════════════════

import { create } from 'zustand';

// Time range types
export type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';

export interface CustomTimeRange {
  start: number; // Unix timestamp
  end: number;   // Unix timestamp
}

export const timeRanges: Record<TimeRange, { hours: number; label: string }> = {
  '1h': { hours: 1, label: '1H' },
  '6h': { hours: 6, label: '6H' },
  '24h': { hours: 24, label: '24H' },
  '7d': { hours: 168, label: '7D' },
  '30d': { hours: 720, label: '30D' },
  'custom': { hours: 0, label: 'Custom' },
};

export const getTimeRangeTimestamps = (range: TimeRange): { start: number; end: number } => {
  const end = Math.floor(Date.now() / 1000);
  if (range === 'custom') {
    return { start: end - 3600, end }; // Default 1 hour for custom
  }
  const hours = timeRanges[range].hours;
  const seconds = hours * 3600;
  return { start: end - seconds, end };
};

// Sidebar localStorage keys (namespaced)
const STORAGE_SIDEBAR_COLLAPSED = 'soc:sidebar:collapsed';
const STORAGE_SIDEBAR_GROUPS = 'soc:sidebar:groups';

// Nav group names (matches Sidebar.tsx NAV_GROUPS)
const NAV_GROUP_NAMES = ['Overview', 'Analytics', 'Threats', 'Systems', 'Rules', 'Logs', 'Config'];

// Load persisted sidebar state from localStorage
function loadSidebarState() {
  const collapsed = localStorage.getItem(STORAGE_SIDEBAR_COLLAPSED);
  const groupsJson = localStorage.getItem(STORAGE_SIDEBAR_GROUPS);
  return {
    sidebarCollapsed: collapsed === 'true',
    expandedGroups: groupsJson
      ? JSON.parse(groupsJson) as Record<string, boolean>
      : Object.fromEntries(NAV_GROUP_NAMES.map((g) => [g, true])),
  };
}

// Persist sidebar state to localStorage
function saveSidebarState(collapsed: boolean, groups: Record<string, boolean>) {
  localStorage.setItem(STORAGE_SIDEBAR_COLLAPSED, String(collapsed));
  localStorage.setItem(STORAGE_SIDEBAR_GROUPS, JSON.stringify(groups));
}

interface AppState {
  // Navigation
  activeTab: string;
  setActiveTab: (tab: string) => void;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  expandedGroups: Record<string, boolean>;
  toggleGroup: (name: string) => void;

  // Mobile menu
  mobileMenuOpen: boolean;
  setMobileMenuOpen: (open: boolean) => void;
  toggleMobileMenu: () => void;
  
  // Theme
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  
  // Loading state
  loading: boolean;
  setLoading: (loading: boolean) => void;
  
  // Last data refresh timestamp
  lastRefresh: number;
  refreshData: () => void;

  // Quick filter
  quickFilter: string;
  setQuickFilter: (filter: string) => void;
  quickFilterType: string;
  setQuickFilterType: (type: string) => void;

  //  connection status
  Connected: boolean;
  setConnected: (connected: boolean) => void;

  // Severity filter (cross-tab: Overview cards → Alerts)
  filterSeverity: '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  setFilterSeverity: (sev: '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') => void;

  // Time range (Grafana-like time selection)
  timeRange: TimeRange;
  setTimeRange: (range: TimeRange) => void;
  customTimeRange?: CustomTimeRange;
  setCustomTimeRange: (range?: CustomTimeRange) => void;
}

const DEFAULT_TABS = [
  'overview', 'heatmap', 'flows', 'ipflow', 'alerts', 'mutes',
  'zenarmor', 'ids', 'geo', 'opnsense', 'rules', 'syslogs',
  'services', 'settings', 'logs', 'network', 'wan-flap', 'rules-classified',
];

const persistedSidebar = loadSidebarState();

export const useStore = create<AppState>((set) => ({
  activeTab: 'overview',
  setActiveTab: (tab) => set({ activeTab: tab }),
  sidebarCollapsed: persistedSidebar.sidebarCollapsed,
  toggleSidebar: () => set((s) => {
    const next = !s.sidebarCollapsed;
    saveSidebarState(next, s.expandedGroups);
    return { sidebarCollapsed: next };
  }),
  expandedGroups: persistedSidebar.expandedGroups,
  toggleGroup: (name) => set((s) => {
    const next = { ...s.expandedGroups, [name]: !s.expandedGroups[name] };
    saveSidebarState(s.sidebarCollapsed, next);
    return { expandedGroups: next };
  }),
  mobileMenuOpen: false,
  setMobileMenuOpen: (open: boolean) => set({ mobileMenuOpen: open }),
  toggleMobileMenu: () => set((s) => ({ mobileMenuOpen: !s.mobileMenuOpen })),
  
  theme: 'dark',
  toggleTheme: () => set((s) => ({ theme: s.theme === 'dark' ? 'light' : 'dark' })),
  loading: false,
  setLoading: (loading) => set({ loading }),
  lastRefresh: 0,
  refreshData: () => set({ lastRefresh: Date.now() }),
  quickFilter: '',
  setQuickFilter: (filter) => set({ quickFilter: filter }),
  quickFilterType: 'all',
  setQuickFilterType: (type) => set({ quickFilterType: type }),
  Connected: false,
  setConnected: (connected: boolean) => set({ Connected: connected }),
  filterSeverity: '',
  setFilterSeverity: (sev: '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') => set({ filterSeverity: sev }),
  timeRange: '24h',
  setTimeRange: (range: TimeRange) => set({ timeRange: range }),
  customTimeRange: undefined,
  setCustomTimeRange: (range?: CustomTimeRange) => set({ customTimeRange: range }),
}));