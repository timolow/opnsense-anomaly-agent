// ═══════════════════════════════════════════════════
// Services Tab - Service monitoring
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { ServiceStatusData } from '@/types';
import { Cpu, Server, Database, Wifi, GitBranch } from 'lucide-react';

import { ServicesSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

export default function ServicesTab() {
  const { data, isLoading, isError, error, refetch } = useQuery<ServiceStatusData>({
    queryKey: ['service-status'],
    queryFn: api.serviceStatus,
    refetchInterval: 30000,
  });

  if (isLoading) return <ServicesSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="Services" />;

  const statusIcon = (s: string) => {
    const up = ['up', 'running', 'ok', 'online', 'active'].includes(s.toLowerCase());
    return up ? '🟢' : '🔴';
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
          <Cpu size={16} className="text-cyber-green" />
        </div>
        <h2 className="text-lg font-bold">Services</h2>
      </div>

      {/* Service Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.dhcp && (
          <div className="cyber-card p-4 cyber-card-hover">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
                <Server size={20} className="text-cyber-accent" />
              </div>
              <div className="flex-1">
                <div className="font-bold">DHCP</div>
                <div className="text-xs text-cyber-textMuted">{data.dhcp.status}</div>
              </div>
              <div className="text-2xl">{statusIcon(data.dhcp.status)}</div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div><span className="text-cyber-textMuted">Active Leases</span><div className="font-mono">{data.dhcp.active_leases}</div></div>
              <div><span className="text-cyber-textMuted">Total Leases</span><div className="font-mono">{data.dhcp.leases}</div></div>
            </div>
            {data.dhcp.details && <div className="mt-2 text-xs text-cyber-textMuted">{data.dhcp.details}</div>}
          </div>
        )}

        {data.unbound && (
          <div className="cyber-card p-4 cyber-card-hover">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-cyber-purple/10 border border-cyber-purple/20 flex items-center justify-center">
                <Wifi size={20} className="text-cyber-purple" />
              </div>
              <div className="flex-1">
                <div className="font-bold">Unbound DNS</div>
                <div className="text-xs text-cyber-textMuted">{data.unbound.status}</div>
              </div>
              <div className="text-2xl">{statusIcon(data.unbound.status)}</div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div><span className="text-cyber-textMuted">Cache Size</span><div className="font-mono">{data.unbound.cache_size}</div></div>
              <div><span className="text-cyber-textMuted">Queries Total</span><div className="font-mono">{(data.unbound.queries_total || 0).toLocaleString()}</div></div>
            </div>
            {data.unbound.details && <div className="mt-2 text-xs text-cyber-textMuted">{data.unbound.details}</div>}
          </div>
        )}

        {data.ntp && (
          <div className="cyber-card p-4 cyber-card-hover">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-cyber-yellow/10 border border-cyber-yellow/20 flex items-center justify-center">
                <Database size={20} className="text-cyber-yellow" />
              </div>
              <div className="flex-1">
                <div className="font-bold">NTP</div>
                <div className="text-xs text-cyber-textMuted">{data.ntp.status}</div>
              </div>
              <div className="text-2xl">{statusIcon(data.ntp.status)}</div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div><span className="text-cyber-textMuted">Server</span><div className="font-mono">{data.ntp.server}</div></div>
              <div><span className="text-cyber-textMuted">Offset</span><div className="font-mono">{data.ntp.offset.toFixed(3)}ms</div></div>
            </div>
            {data.ntp.details && <div className="mt-2 text-xs text-cyber-textMuted">{data.ntp.details}</div>}
          </div>
        )}

        {data.openvpn && (
          <div className="cyber-card p-4 cyber-card-hover">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
                <GitBranch size={20} className="text-cyber-green" />
              </div>
              <div className="flex-1">
                <div className="font-bold">OpenVPN</div>
                <div className="text-xs text-cyber-textMuted">{data.openvpn.status}</div>
              </div>
              <div className="text-2xl">{statusIcon(data.openvpn.status)}</div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div><span className="text-cyber-textMuted">Connections</span><div className="font-mono">{data.openvpn.connections}</div></div>
              <div><span className="text-cyber-textMuted">Bytes In/Out</span><div className="font-mono">{data.openvpn.bytes_in}/{data.openvpn.bytes_out}</div></div>
            </div>
            {data.openvpn.details && <div className="mt-2 text-xs text-cyber-textMuted">{data.openvpn.details}</div>}
          </div>
        )}

        {data.wireguard && (
          <div className="cyber-card p-4 cyber-card-hover">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-cyber-pink/10 border border-cyber-pink/20 flex items-center justify-center">
                <GitBranch size={20} className="text-cyber-pink" />
              </div>
              <div className="flex-1">
                <div className="font-bold">WireGuard</div>
                <div className="text-xs text-cyber-textMuted">{data.wireguard.status}</div>
              </div>
              <div className="text-2xl">{statusIcon(data.wireguard.status)}</div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div><span className="text-cyber-textMuted">Connections</span><div className="font-mono">{data.wireguard.connections}</div></div>
              <div><span className="text-cyber-textMuted">Bytes In/Out</span><div className="font-mono">{data.wireguard.bytes_in}/{data.wireguard.bytes_out}</div></div>
            </div>
            {data.wireguard.details && <div className="mt-2 text-xs text-cyber-textMuted">{data.wireguard.details}</div>}
          </div>
        )}
      </div>

      {/* Service Alerts */}
      {data.alerts.length > 0 && (
        <div className="cyber-card p-4">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Service Alerts</h3>
          <div className="space-y-2">
            {data.alerts.map((alert, i) => (
              <div key={i} className={`flex items-center gap-3 p-3 rounded bg-cyber-panelHover border-l-2 ${
                alert.severity === 'CRITICAL' ? 'border-cyber-red' : 'border-cyber-yellow'
              }`}>
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  alert.severity === 'CRITICAL' ? 'bg-cyber-red animate-pulse' : 'bg-cyber-yellow animate-pulse'
                }`} />
                <span className="font-semibold text-sm">{alert.service}</span>
                <span className="text-sm flex-1">{alert.message}</span>
                <span className="font-mono text-xs text-cyber-textMuted">{alert.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
