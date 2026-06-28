// ═══════════════════════════════════════════════════
// ServicesViewTab - Merged: Services + Nginx
// Sub-tabs for each service monitoring type
// ═══════════════════════════════════════════════════

import { useState } from 'react';
import { Cpu, Wifi } from 'lucide-react';
import ServicesTab from './ServicesTab';
import { NginxTab } from './NginxTab';

type ServicesSubTab = 'services' | 'nginx';

// ── Sub-tab bar ──
function SubTabBar({ active, onChange }: { active: ServicesSubTab; onChange: (t: ServicesSubTab) => void }) {
  const tabs: { id: ServicesSubTab; label: string; icon: React.ReactNode; desc: string }[] = [
    { id: 'services', label: 'Services', icon: <Cpu size={14} />, desc: 'DHCP, DNS, NTP, VPN' },
    { id: 'nginx', label: 'Nginx', icon: <Wifi size={14} />, desc: 'Web server traffic' },
  ];

  return (
    <div className="flex gap-1 bg-cyber-panel/50 border border-cyber-border rounded-lg p-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          title={t.desc}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-md text-sm font-medium transition-all cursor-pointer ${
            active === t.id
              ? 'bg-cyber-accent/15 text-cyber-accent shadow-[inset_0_0_15px_rgba(0,229,255,0.05)]'
              : 'text-cyber-textMuted hover:text-cyber-text hover:bg-cyber-panelHover'
          }`}
        >
          {t.icon}
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Main ServicesViewTab Component
// ═══════════════════════════════════════════════════
export default function ServicesViewTab() {
  const [subTab, setSubTab] = useState<ServicesSubTab>('services');

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
          <Cpu size={16} className="text-cyber-green" />
        </div>
        <h2 className="text-lg font-bold">Services</h2>
      </div>

      {/* Sub-tab navigation */}
      <SubTabBar active={subTab} onChange={setSubTab} />

      {/* Sub-tab content */}
      {subTab === 'services' && <ServicesTab />}
      {subTab === 'nginx' && <NginxTab />}
    </div>
  );
}
