// ═══════════════════════════════════════════════════
// TrafficTab - Merged: Flow Map + IP Flow
// Sub-tabs for visual flow map and detailed IP flow table
// ═══════════════════════════════════════════════════

import { useState } from 'react';
import { GitMerge, Network, Activity, ArrowUpRight, ArrowDownLeft } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { IpFlowData } from '@/types';
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

  // Fetch flow data once for the metrics row
  const { data: flowData } = useQuery<IpFlowData>({
    queryKey: ['ip-flow-metrics'],
    queryFn: api.ipFlow,
    refetchInterval: 30000,
  });

  // Compute metrics from flow data
  const metrics = flowData ? (() => {
    const nodes = flowData.nodes || [];
    const edges = flowData.edges || [];
    const totalEvents = edges.reduce((sum, e) => sum + (e.value || 0), 0);
    const uniqueSrc = new Set(edges.map(e => e.source)).size;
    const uniqueDst = new Set(edges.map(e => e.target)).size;
    const categories = new Set(nodes.map(n => n.category)).size;
    return { nodes: nodes.length, edges: edges.length, totalEvents, uniqueSrc, uniqueDst, categories };
  })() : null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
          <GitMerge size={16} className="text-cyber-purple" />
        </div>
        <h2 className="text-lg font-bold">Traffic</h2>
      </div>

      {/* Metric cards */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <Activity size={14} className="text-cyber-accent" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Events</span>
            </div>
            <div className="text-xl font-bold font-mono text-cyber-accent">{metrics.totalEvents.toLocaleString()}</div>
          </div>
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <ArrowUpRight size={14} className="text-neon-pink" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Unique Sources</span>
            </div>
            <div className="text-xl font-bold font-mono text-neon-pink">{metrics.uniqueSrc}</div>
          </div>
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <ArrowDownLeft size={14} className="text-neon-green" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Unique Destinations</span>
            </div>
            <div className="text-xl font-bold font-mono text-neon-green">{metrics.uniqueDst}</div>
          </div>
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <GitMerge size={14} className="text-neon-purple" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Flows</span>
            </div>
            <div className="text-xl font-bold font-mono text-neon-purple">{metrics.edges}</div>
          </div>
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <Network size={14} className="text-cyber-green" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Nodes</span>
            </div>
            <div className="text-xl font-bold font-mono text-cyber-green">{metrics.nodes}</div>
          </div>
          <div className="cyber-card p-3 cyber-card-hover">
            <div className="flex items-center gap-2 mb-1">
              <Activity size={14} className="text-cyber-yellow" />
              <span className="text-xs text-cyber-textMuted uppercase tracking-wider">Categories</span>
            </div>
            <div className="text-xl font-bold font-mono text-cyber-yellow">{metrics.categories}</div>
          </div>
        </div>
      )}

      {/* Sub-tab navigation */}
      <SubTabBar active={subTab} onChange={setSubTab} />

      {/* Sub-tab content */}
      {subTab === 'flow-map' && <FlowsTab />}
      {subTab === 'ip-flow' && <IpFlowTab />}
    </div>
  );
}
