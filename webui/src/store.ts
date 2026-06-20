// ═══════════════════════════════════════════════════
// Store - Zustand state management
// ═══════════════════════════════════════════════════

import { create } from 'zustand';

interface AppState {
  // Navigation
  activeTab: string;
  setActiveTab: (tab: string) => void;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  
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
  setConnected: (connected) => set({ Connected: connected }),
}));
