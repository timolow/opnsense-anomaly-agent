// ═══════════════════════════════════════════════════
// TrafficTab - Merged: Flow Map + IP Flow
// Sub-tabs for visual flow map and detailed IP flow table
// ═══════════════════════════════════════════════════

import { useState } from 'react';
import { GitMerge, Network } from 'lucide-react';
import FlowsTab from './FlowsTab';
import IpFlowTab from './IpFlowTab';

type TrafficSubTab = 'flow-map' | 'ip-flow';

// ── Sub-tab bar ──
function SubTabBar({ active, onChange }: { active: TrafficSubTab; onChange: (t: TrafficSubTab) => void }) {
  const tabs: { id: TrafficSubTab; label: string; icon: React.ReactNode; desc: string }[] = [
    { id: 'flow-map', label: 'Flow Map', icon: <GitMerge size={14} />, desc: 'Visual network flow diagram' },
    { id: 'ip-flow', label: 'IP Flow', icon: <Network size={14} />, desc: 'Detailed IP communication table' },
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
// Main TrafficTab Component
// ═══════════════════════════════════════════════════
export default function TrafficTab() {
  const [subTab, setSubTab] = useState<TrafficSubTab>('flow-map');

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <GitMerge size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">Traffic</h2>
      </div>

      {/* Sub-tab navigation */}
      <SubTabBar active={subTab} onChange={setSubTab} />

      {/* Sub-tab content */}
      {subTab === 'flow-map' && <FlowsTab />}
      {subTab === 'ip-flow' && <IpFlowTab />}
    </div>
  );
}
