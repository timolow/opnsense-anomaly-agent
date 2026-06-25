// ═══════════════════════════════════════════════════
// Sidebar Component - Cyberpunk navigation
// ═══════════════════════════════════════════════════

import { useStore } from '../store';
import {
  LayoutDashboard, Map, GitMerge, Network, ShieldAlert,
  Ban, Shield, Eye, Globe, Settings, Server, FileText,
  Activity, Cpu, Radio, Layers, TrendingUp, Database,
  Menu, X, ChevronDown, ChevronRight,
  Flame, Wifi,
} from 'lucide-react';

interface NavGroup {
  name: string;
  icon: React.ReactNode;
  items: { id: string; label: string; icon: React.ReactNode }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    name: 'Overview',
    icon: <LayoutDashboard size={16} />,
    items: [
      { id: 'overview', label: 'Dashboard', icon: <LayoutDashboard size={14} /> },
    ],
  },
  {
    name: 'Analytics',
    icon: <Flame size={16} />,
    items: [
      { id: 'heatmap', label: 'Heatmap', icon: <Flame size={14} /> },
      { id: 'flows', label: 'Flow Map', icon: <GitMerge size={14} /> },
      { id: 'ipflow', label: 'IP Flow', icon: <Network size={14} /> },
      { id: 'geo', label: 'Geography', icon: <Globe size={14} /> },
    ],
  },
  {
    name: 'Threats',
    icon: <ShieldAlert size={16} />,
    items: [
      { id: 'alerts', label: 'Alerts', icon: <ShieldAlert size={14} /> },
      { id: 'mutes', label: 'Mutes', icon: <Ban size={14} /> },
      { id: 'zenarmor', label: 'ZenArmor', icon: <Shield size={14} /> },
      { id: 'ids', label: 'IDS', icon: <Eye size={14} /> },
    ],
  },
  {
    name: 'Systems',
    icon: <Server size={16} />,
    items: [
      { id: 'opnsense', label: 'OPNsense', icon: <Server size={14} /> },
      { id: 'services', label: 'Services', icon: <Cpu size={14} /> },
      { id: 'nginx', label: 'Nginx', icon: <Wifi size={14} /> },
      { id: 'network', label: 'Network', icon: <Network size={14} /> },
      { id: 'wan-flap', label: 'WAN Flap', icon: <Radio size={14} /> },
    ],
  },
  {
    name: 'Rules',
    icon: <Layers size={16} />,
    items: [
      { id: 'rules', label: 'Firewall Rules', icon: <Layers size={14} /> },
      { id: 'rules-classified', label: 'Rules ML', icon: <TrendingUp size={14} /> },
    ],
  },
  {
    name: 'Logs',
    icon: <FileText size={16} />,
    items: [
      { id: 'syslogs', label: 'Syslogs', icon: <FileText size={14} /> },
      { id: 'logs', label: 'Query Logs', icon: <Database size={14} /> },
    ],
  },
  {
    name: 'Config',
    icon: <Settings size={16} />,
    items: [
      { id: 'settings', label: 'Settings', icon: <Settings size={14} /> },
    ],
  },
];

export default function Sidebar() {
  const { activeTab, setActiveTab, sidebarCollapsed, toggleSidebar, expandedGroups, toggleGroup, mobileMenuOpen, setMobileMenuOpen } = useStore();

  // Map tab IDs to their group names — the active tab's group is always expanded
  const tabToGroup: Record<string, string> = {
    overview: 'Overview',
    heatmap: 'Analytics',
    flows: 'Analytics',
    ipflow: 'Analytics',
    geo: 'Analytics',
    alerts: 'Threats',
    mutes: 'Threats',
    zenarmor: 'Threats',
    ids: 'Threats',
    opnsense: 'Systems',
    services: 'Systems',
    nginx: 'Systems',
    network: 'Systems',
    'wan-flap': 'Systems',
    rules: 'Rules',
    'rules-classified': 'Rules',
    syslogs: 'Logs',
    logs: 'Logs',
    settings: 'Config',
  };

  // Display-expanded groups: persisted state + always expand active tab's group
  const activeGroup = tabToGroup[activeTab] || '';
  const displayGroups: Record<string, boolean> = {};
  for (const group of NAV_GROUPS) {
    displayGroups[group.name] = group.name === activeGroup || expandedGroups[group.name];
  }

  const handleTabClick = (tabId: string) => {
    setActiveTab(tabId);
    window.location.hash = '#' + tabId;
    setMobileMenuOpen(false);
  };

  // On desktop, sidebar is always visible with collapse toggle
  // On mobile, sidebar is overlay controlled by mobileMenuOpen
  const isDesktop = typeof window !== 'undefined' && window.matchMedia('(min-width: 1024px)').matches;
  const showSidebar = isDesktop || mobileMenuOpen;

  return (
    <aside
      className={`flex flex-col bg-gradient-to-b from-cyber-panel to-cyber-darker border-r border-cyber-border
        transition-all duration-300
        ${showSidebar ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        ${sidebarCollapsed ? 'w-14' : 'w-60'}
        fixed left-0 top-0 bottom-0 z-50 lg:z-30`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-14 border-b border-cyber-border flex-shrink-0">
        <div className="w-8 h-8 rounded-md bg-gradient-to-br from-cyber-accent to-cyber-purple flex items-center justify-center shadow-neon-cyan flex-shrink-0">
          <Activity size={18} className="text-cyber-darker" />
        </div>
        {!sidebarCollapsed && (
          <span className="text-sm font-bold tracking-wider text-gradient-cyber">
            SOC DASHBOARD
          </span>
        )}
        {/* Mobile close button */}
        <button
          onClick={() => setMobileMenuOpen(false)}
          className="lg:hidden ml-auto w-6 h-6 rounded-full bg-cyber-accent/20 border border-cyber-accent/30 flex items-center justify-center text-cyber-accent hover:bg-cyber-accent/30 flex-shrink-0"
        >
          <X size={12} />
        </button>
        {/* Desktop collapse toggle */}
        <button
          onClick={toggleSidebar}
          className="hidden lg:flex ml-auto w-6 h-6 rounded-full bg-cyber-accent/20 border border-cyber-accent/30 flex items-center justify-center text-cyber-accent hover:bg-cyber-accent/30 flex-shrink-0"
        >
          {sidebarCollapsed ? <Menu size={12} /> : <X size={12} />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        {NAV_GROUPS.map((group) => (
          <div key={group.name} className="mb-1">
            {!sidebarCollapsed && (
              <button
                onClick={() => toggleGroup(group.name)}
                className="w-full flex items-center gap-2 px-4 py-2 text-xs font-semibold uppercase tracking-wider text-cyber-textMuted hover:text-cyber-text"
              >
                {group.icon}
                <span className="flex-1 text-left">{group.name}</span>
                {displayGroups[group.name] ? (
                  <ChevronDown size={12} />
                ) : (
                  <ChevronRight size={12} />
                )}
              </button>
            )}
            {(sidebarCollapsed || displayGroups[group.name]) && (
              <div className={`${sidebarCollapsed ? '' : 'ml-4 space-y-0.5'}`}>
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => handleTabClick(item.id)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2.5 min-h-[44px] rounded-md text-sm transition-all duration-150
                      ${activeTab === item.id
                        ? 'bg-cyber-accent/10 text-cyber-accent border-l-2 border-cyber-accent shadow-[inset_0_0_20px_rgba(0,229,255,0.05)]'
                        : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panelHover'
                      }`}
                    title={sidebarCollapsed ? item.label : undefined}
                  >
                    {item.icon}
                    {!sidebarCollapsed && <span className="flex-1 text-left truncate">{item.label}</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </nav>

      {/* System Health */}
      {!sidebarCollapsed && (
        <div className="border-t border-cyber-border p-4 flex-shrink-0">
          <div className="text-xs font-semibold uppercase tracking-wider text-cyber-textMuted mb-3">System Health</div>
          <div className="flex flex-wrap gap-2">
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-cyber-panelHover text-xs">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              <span className="text-cyber-textMuted">Postgres</span>
            </div>
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-cyber-panelHover text-xs">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              <span className="text-cyber-textMuted">Redis</span>
            </div>
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-cyber-panelHover text-xs">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              <span className="text-cyber-textMuted">OPNsense</span>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 px-2">
            <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
            <span className="text-xs text-cyber-textMuted">Agent Running</span>
          </div>
        </div>
      )}
    </aside>
  );
}