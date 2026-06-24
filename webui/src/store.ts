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

interface AppState {
  // Navigation
  activeTab: string;
  setActiveTab: (tab: string) => void;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  
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

  // Per-tab loading/error state (for TabShell)
  tabLoadingState: Record<string, { loading: boolean; error: string | null }>;
  setTabLoadingState: (tab: string, state: { loading: boolean; error: string | null }) => void;

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

export const useStore = create<AppState>((set) => ({
  activeTab: 'overview',
  setActiveTab: (tab) => set({ activeTab: tab }),
  sidebarCollapsed: false,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
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
  tabLoadingState: {},
  setTabLoadingState: (tab: string, state: { loading: boolean; error: string | null }) =>
    set((s) => ({ tabLoadingState: { ...s.tabLoadingState, [tab]: state } })),
  timeRange: '24h',
  setTimeRange: (range: TimeRange) => set({ timeRange: range }),
  customTimeRange: undefined,
  setCustomTimeRange: (range?: CustomTimeRange) => set({ customTimeRange: range }),
}));