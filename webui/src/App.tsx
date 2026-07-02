// ═══════════════════════════════════════════════════
// Main App - React entry with sidebar and content area
// 11 focused tabs (consolidated from 19)
// ═══════════════════════════════════════════════════

import { Suspense, useEffect } from 'react';
import { useStore } from './store';
import Sidebar from './components/Sidebar';
import TimeRangePicker from './components/TimeRangePicker';
import { Menu } from 'lucide-react';
import { TabShell } from './components/TabShell';

// ── Tab Components (11 focused views) ──
import OverviewTab from './components/tabs/OverviewTab';
import HeatmapTab from './components/tabs/HeatmapTab';
import TrafficTab from './components/tabs/TrafficTab';
import AlertsTab from './components/tabs/AlertsTab';
import RulesClassifiedTab from './components/tabs/RulesClassifiedTab';
import LogsTab from './components/tabs/LogsTab';
import SettingsTab from './components/tabs/SettingsTab';
import BehavioralOverviewTab from './components/tabs/BehavioralOverviewTab';
import IpProfilesTab from './components/tabs/IpProfilesTab';
import ThreatCanvasTab from './components/tabs/ThreatCanvasTab';
import BehavioralBaselinesTab from './components/tabs/BehavioralBaselinesTab';

const TAB_TITLE: Record<string, string> = {
  overview: 'Dashboard',
  heatmap: 'Heatmap',
  traffic: 'Traffic',
  alerts: 'Alerts',
  'rules-classified': 'Rules ML',
  logs: 'Logs',
  settings: 'Settings',
  'behavioral-overview': 'Behavioral Overview',
  'ip-profiles': 'IP Profiles',
  'threat-canvas': 'Threat Canvas',
  'behavioral-baselines': 'Baselines',
};

function TabContent({ tab }: { tab: string }) {
  const title = TAB_TITLE[tab] || 'Dashboard';
  return (
    <TabShell tab={tab} tabName={title}>
      {(() => {
        switch (tab) {
          case 'overview': return <OverviewTab />;
          case 'heatmap': return <HeatmapTab />;
          case 'traffic': return <TrafficTab />;
          case 'alerts': return <AlertsTab />;
          case 'rules-classified': return <RulesClassifiedTab />;
          case 'logs': return <LogsTab />;
          case 'settings': return <SettingsTab />;
          case 'behavioral-overview': return <BehavioralOverviewTab />;
          case 'ip-profiles': return <IpProfilesTab />;
          case 'threat-canvas': return <ThreatCanvasTab />;
          case 'behavioral-baselines': return <BehavioralBaselinesTab />;
          // Redirect removed tabs
          case 'flow-classification': case 'incident-timeline': return <ThreatCanvasTab />;
          case 'network': case 'wan-flap': case 'services': case 'observability': return <LogsTab />;
          case '': return <OverviewTab />;
          default: return <OverviewTab />;
        }
      })()}
    </TabShell>
  );
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
    // Normalize URL hash to match tab IDs (legacy redirects)
    const urlToTab = (url: string) => {
      const hash = window.location.hash.slice(1).replace(/^\//, '');
      const map: Record<string, string> = {
        // Legacy redirects to new merged tabs
        'firewall-rules': 'rules-classified',
        'firerules': 'rules-classified',
        'rules-ml': 'rules-classified',
        'rulesml': 'rules-classified',
        'rules': 'rules-classified',
        'flow-map': 'traffic',
        'flowmap': 'traffic',
        'flows': 'traffic',
        'ip-flow': 'traffic',
        'ipflow': 'traffic',
        'syslogs': 'logs',
        'dns-queries': 'logs',
        'dns': 'logs',
        'query-logs': 'logs',
        'nginx': 'services',
        'opnsense': 'services',
        'wanflap': 'wan-flap',
        'wan-flap': 'wan-flap',
        'network-topology': 'network',
        'threat-alerts': 'alerts',
        'mutes': 'alerts',
        'zenarmor': 'alerts',
        'ids': 'alerts',
        'traffic-heatmap': 'heatmap',
        'geo': 'heatmap',
        'geography': 'heatmap',
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
            <h1 className="text-sm md:text-lg font-semibold text-cyber-text truncate">{TAB_TITLE[activeTab] || 'Dashboard'}</h1>
          </div>
          
          <div className="flex items-center gap-2 md:gap-3">
            <TimeRangePicker />
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
