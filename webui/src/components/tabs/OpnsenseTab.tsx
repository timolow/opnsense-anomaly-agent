// ═══════════════════════════════════════════════════
// OPNsense Tab - Firewall status and interface details
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { OpnsenseStatusData } from '@/types';
import { Server, Cpu, MemoryStick, HardDrive, Network } from 'lucide-react';

export default function OpnsenseTab() {
  const { data } = useQuery<OpnsenseStatusData>({
    queryKey: ['opnsense'],
    queryFn: api.opnsense,
    refetchInterval: 30000,
  });

  if (!data) return <div className="flex items-center justify-center h-64"><div className="cyber-skeleton w-8 h-8 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" /></div>;

  const statusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'up': case 'ok': case 'online': return '🟢';
      case 'down': case 'error': case 'offline': return '🔴';
      default: return '🟡';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
          <Server size={16} className="text-cyber-green" />
        </div>
        <h2 className="text-lg font-bold">OPNsense Status</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{data.version}</span>
      </div>

      {/* System Info */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Cpu size={14} className="text-cyber-accent" />
            <span className="cyber-stat-label">CPU</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-cyan">{data.cpu_usage}%</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <MemoryStick size={14} className="text-cyber-pink" />
            <span className="cyber-stat-label">Memory</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-pink">{data.memory_usage}%</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <HardDrive size={14} className="text-cyber-purple" />
            <span className="cyber-stat-label">Uptime</span>
          </div>
          <div className="text-lg font-bold font-mono text-neon-purple">{data.uptime}</div>
        </div>
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Network size={14} className="text-cyber-green" />
            <span className="cyber-stat-label">Interfaces</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-green">{data.interfaces.length}</div>
        </div>
      </div>

      {/* Interfaces */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Interfaces</h3>
        <div className="cyber-table-responsive"><table className="cyber-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Name</th>
              <th>Description</th>
              <th>IPv4</th>
              <th>IPv6</th>
              <th>MAC</th>
            </tr>
          </thead>
          <tbody>
            {data.interfaces.map((iface, i) => (
              <tr key={i}>
                <td className="text-lg">{statusIcon(iface.status)}</td>
                <td className="font-bold font-mono">{iface.name}</td>
                <td>{iface.description}</td>
                <td className="font-mono">{iface.ipv4}</td>
                <td className="font-mono">{iface.ipv6}</td>
                <td className="font-mono">{iface.mac}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>

      {/* Gateways */}
      <div className="cyber-card p-4 scanlines">
        <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Gateways</h3>
        <div className="cyber-table-responsive"><table className="cyber-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Gateway IP</th>
              <th>Interface</th>
              <th>Delay</th>
              <th>Loss</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.gateways.map((gw, i) => (
              <tr key={i}>
                <td className="font-semibold">{gw.name}</td>
                <td className="font-mono">{gw.gateway_ip}</td>
                <td>{gw.interface}</td>
                <td className="font-mono">{gw.delay}ms</td>
                <td className="font-mono">{gw.loss}%</td>
                <td>
                  <span className={`cyber-badge ${gw.status === 'up' ? 'cyber-badge-pass' : 'cyber-badge-warning'}`}>
                    {gw.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
