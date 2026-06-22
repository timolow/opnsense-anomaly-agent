// ═══════════════════════════════════════════════════
// Main App - React entry with sidebar and content area
// ═══════════════════════════════════════════════════

import { Suspense, lazy, useEffect } from 'react';
import { useStore } from './store';
import Sidebar from './components/Sidebar';
import TimeRangePicker from './components/TimeRangePicker';
import { Menu } from 'lucide-react';

// ── Tab Components ──
import OverviewTab from './components/tabs/OverviewTab';
import HeatmapTab from './components/tabs/HeatmapTab';
import FlowsTab from './components/tabs/FlowsTab';
import IpFlowTab from './components/tabs/IpFlowTab';
import AlertsTab from './components/tabs/AlertsTab';
import MutesTab from './components/tabs/MutesTab';
import ZenArmorTab from './components/tabs/ZenArmorTab';
import IdsTab from './components/tabs/IdsTab';
import GeoTab from './components/tabs/GeoTab';
import OpnsenseTab from './components/tabs/OpnsenseTab';
import RulesTab from './components/tabs/RulesTab';
import SyslogsTab from './components/tabs/SyslogsTab';
import ServicesTab from './components/tabs/ServicesTab';
import SettingsTab from './components/tabs/SettingsTab';
import LogsQueryTab from './components/tabs/LogsQueryTab';
import NetworkTab from './components/tabs/NetworkTab';
import WanFlapTab from './components/tabs/WanFlapTab';
import RulesClassifiedTab from './components/tabs/RulesClassifiedTab';
import NginxTab from './components/tabs/NginxTab';

const TAB_TITLE: Record<string, string> = {
  overview: 'Overview',
  heatmap: 'Traffic Heatmap',
  flows: 'Flow Map',
  ipflow: 'IP Flow',
  alerts: 'Threat Alerts',
  mutes: 'Mutes',
  zenarmor: 'ZenArmor',
  ids: 'IDS',
  geo: 'Geography',
  opnsense: 'OPNsense Status',
  rules: 'Firewall Rules',
  syslogs: 'Syslogs',
  services: 'Services',
  settings: 'Settings',
  logs: 'Query Logs',
  network: 'Network Topology',
  'wan-flap': 'WAN Flap Detection',
  'rules-classified': 'Rules ML',
  nginx: 'Nginx Monitor',
};

function TabContent({ tab }: { tab: string }) {
  switch (tab) {
    case 'overview': return <OverviewTab />;
    case 'heatmap': return <HeatmapTab />;
    case 'flows': return <FlowsTab />;
    case 'ipflow': return <IpFlowTab />;
    case 'alerts': return <AlertsTab />;
    case 'mutes': return <MutesTab />;
    case 'zenarmor': return <ZenArmorTab />;
    case 'ids': return <IdsTab />;
    case 'geo': return <GeoTab />;
    case 'opnsense': return <OpnsenseTab />;
    case 'rules': return <RulesTab />;
    case 'syslogs': return <SyslogsTab />;
    case 'services': return <ServicesTab />;
    case 'settings': return <SettingsTab />;
    case 'logs': return <LogsQueryTab />;
    case 'network': return <NetworkTab />;
    case 'wan-flap': return <WanFlapTab />;
    case 'rules-classified': return <RulesClassifiedTab />;
    case '': return <OverviewTab />;
    case 'nginx': return <NginxTab />;
    default: return <OverviewTab />;
  }
}

function LoadingScreen() {
  return (
    <div className="flex items-center justify-center h-screen bg-cyber-darker">
      <div className="text-center">
        <div className="w-12 h-12 mx-auto mb-4 rounded-full border-4 border-cyber-border border-t-cyber-accent animate-spin" />
        <div className="text-lg font-bold text-gradient-cyber">Loading Dashboard...</div>
        <div className="text-xs text-cyber-textMuted mt-2 font-mono">Initializing SOC monitoring</div>
      </div>
    </div>
  );
}

export default function App() {
  const { activeTab, sidebarCollapsed, mobileMenuOpen, setActiveTab, toggleMobileMenu, setMobileMenuOpen } = useStore();
  
  useEffect(() => {
    // Normalize URL hash to match tab IDs
    const urlToTab = (url: string) => {
      const hash = window.location.hash.slice(1);
      const map: Record<string, string> = {
        'firewall-rules': 'rules',
        'rules-ml': 'rules-classified',
        'wan-flap': 'wan-flap',
        'network-topology': 'network',
        'threat-alerts': 'alerts',
        'traffic-heatmap': 'heatmap',
        'flow-map': 'flows',
        'ip-flow': 'ipflow',
        'geo': 'geo',
        'opnsense-status': 'opnsense',
        'system-health': 'settings',
      };
      return map[hash] || hash;
    };
    
    // Sync URL hash with store on mount
    const tab = urlToTab(window.location.href);
    if (tab && tab !== activeTab) {
      setActiveTab(tab);
    }
    
    const handleHashChange = () => {
      const tab = urlToTab(window.location.href);
      if (tab) {
        setActiveTab(tab);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);
  
  // Sync store with URL hash (update URL when activeTab changes)
  useEffect(() => {
    const currentHash = window.location.hash.slice(1);
    // Only update if different from activeTab (avoid loop)
    if (currentHash !== activeTab && activeTab) {
      window.history.replaceState(null, '', '#' + activeTab);
    }
  }, [activeTab]);
  
  useEffect(() => {
    console.log('[App] React mounted, activeTab:', activeTab);
  }, [activeTab]);

  // Desktop sidebar offset
  const sidebarOffset = sidebarCollapsed ? 'lg:ml-14' : 'lg:ml-60';

  return (
    <div className="h-screen flex overflow-hidden bg-cyber-darker">
      <Sidebar />
      
      {/* Mobile overlay backdrop */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
      
      <main
        className={`flex-1 flex flex-col overflow-hidden transition-all duration-300
          ${sidebarOffset}`}
      >
        {/* Top Header */}
        <header className="h-14 bg-cyber-panel border-b border-cyber-border flex items-center justify-between px-4 md:px-6 flex-shrink-0 gap-2">
          <div className="flex items-center gap-2 md:gap-4">
            {/* Mobile hamburger button */}
            <button
              onClick={toggleMobileMenu}
              className="lg:hidden w-11 h-11 rounded-md bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center text-cyber-accent hover:bg-cyber-accent/20 flex-shrink-0"
            >
              <Menu size={16} />
            </button>
            <h1 className="text-sm md:text-lg font-bold text-gradient-cyber truncate">{TAB_TITLE[activeTab] || 'Dashboard'}</h1>
            <span className="text-xs text-cyber-textMuted font-mono hidden md:inline">
              {activeTab} · v2.0.0
            </span>
          </div>
          
          <div className="flex items-center gap-2 md:gap-3">
            <TimeRangePicker />
            <div className="hidden sm:flex items-center gap-2 px-2 md:px-3 py-1 rounded-full bg-cyber-panelHover border border-cyber-border">
              <div className="w-2 h-2 rounded-full bg-cyber-green animate-pulse" />
              <span className="text-xs text-cyber-textMuted">Live</span>
            </div>
            <div className="text-xs text-cyber-textMuted font-mono hidden sm:block">
              {new Date().toLocaleTimeString()}
            </div>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-3 md:p-4 lg:p-6">
          <Suspense fallback={<LoadingScreen />}>
            <TabContent key={activeTab} tab={activeTab} />
          </Suspense>
        </div>
      </main>
    </div>
  );
}