// ═══════════════════════════════════════════════════
// OPNsense Tab - Firewall status and interface details
// ═══════════════════════════════════════════════════

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api';
import type { OpnsenseStatusData } from '@/types';
import { Server, Cpu, MemoryStick, Clock, Network, Shield, Activity, HardDrive } from 'lucide-react';

import { OpnsenseSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError } from '../../components/TabShell';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function formatPackets(count: number): string {
  if (count === 0) return '0';
  if (count >= 1_000_000_000) return `${(count / 1_000_000_000).toFixed(1)}B`;
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1_000) return `${(count / 1_000).toFixed(1)}K`;
  return String(count);
}

export default function OpnsenseTab() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['opnsense'],
    queryFn: api.opnsense,
    refetchInterval: 30000,
  });

  if (isLoading) return <OpnsenseSkeleton />;
  if (isError && error) return <TabQueryError error={error} isError={isError} onRetry={refetch} tabName="OPNsense Status" />;

  const statusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'up': case 'ok': case 'online': case 'connected': return '🟢';
      case 'down': case 'error': case 'offline': case 'fault': return '🔴';
      default: return '🟡';
    }
  };

  const isDisconnected = !data || data.version === 'unknown' || data.version === 'error';

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-md bg-cyber-green/10 border border-cyber-green/20 flex items-center justify-center">
          <Server size={16} className="text-cyber-green" />
        </div>
        <h2 className="text-lg font-bold">OPNsense Status</h2>
        <span className="text-xs text-cyber-textMuted font-mono">{data.version}</span>
        {data.hostname && (
          <span className="text-xs text-cyber-textMuted font-mono">• {data.hostname}</span>
        )}
      </div>

      {/* System Info Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        {/* CPU */}
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Cpu size={14} className="text-cyber-accent" />
            <span className="cyber-stat-label">CPU</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-cyan">
            {data.cpu_usage > 0 ? `${data.cpu_usage}%` : data.cpu_usage === 0 ? '0%' : 'N/A'}
          </div>
          {data.cpu_usage < 0 && <div className="text-[10px] text-cyber-textMuted mt-1">Not exposed by OPNsense API</div>}
        </div>

        {/* Memory */}
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <MemoryStick size={14} className="text-cyber-pink" />
            <span className="cyber-stat-label">Memory</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-pink">
            {data.memory_usage > 0 ? `${data.memory_usage}%` : 'N/A'}
          </div>
          {data.memory_total_gb > 0 && (
            <div className="text-[10px] text-cyber-textMuted mt-1">
              {data.memory_used_gb} GB / {data.memory_total_gb} GB
            </div>
          )}
        </div>

        {/* Uptime */}
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Clock size={14} className="text-cyber-purple" />
            <span className="cyber-stat-label">Uptime</span>
          </div>
          <div className="text-lg font-bold font-mono text-neon-purple">
            {data.uptime || '—'}
          </div>
          {!data.uptime && <div className="text-[10px] text-cyber-textMuted mt-1">Not exposed by OPNsense 26.4</div>}
        </div>

        {/* Interfaces */}
        <div className="cyber-card p-4 cyber-card-hover">
          <div className="flex items-center gap-2 mb-2">
            <Network size={14} className="text-cyber-green" />
            <span className="cyber-stat-label">Interfaces</span>
          </div>
          <div className="text-2xl font-bold font-mono text-neon-green">{data.interfaces.length}</div>
        </div>
      </div>

      {/* Extended Stats Row */}
      {(data.firewall_rules > 0 || data.services_total > 0) && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
          {/* Firewall Rules */}
          {data.firewall_rules > 0 && (
            <div className="cyber-card p-4 cyber-card-hover">
              <div className="flex items-center gap-2 mb-2">
                <Shield size={14} className="text-cyber-orange" />
                <span className="cyber-stat-label">Firewall Rules</span>
              </div>
              <div className="text-2xl font-bold font-mono text-neon-orange">{data.firewall_rules}</div>
            </div>
          )}

          {/* Services Total */}
          {data.services_total > 0 && (
            <div className="cyber-card p-4 cyber-card-hover">
              <div className="flex items-center gap-2 mb-2">
                <Activity size={14} className="text-cyber-cyan" />
                <span className="cyber-stat-label">Services</span>
              </div>
              <div className="text-2xl font-bold font-mono text-neon-cyan">
                {data.services_running}/{data.services_total}
              </div>
              <div className="text-[10px] text-cyber-textMuted mt-1">running / total</div>
            </div>
          )}

          {/* Gateways */}
          {data.gateways.length > 0 && (
            <div className="cyber-card p-4 cyber-card-hover">
              <div className="flex items-center gap-2 mb-2">
                <HardDrive size={14} className="text-cyber-yellow" />
                <span className="cyber-stat-label">Gateways</span>
              </div>
              <div className="text-2xl font-bold font-mono text-neon-yellow">{data.gateways.length}</div>
              <div className="text-[10px] text-cyber-textMuted mt-1">
                {data.gateways.filter(g => g.status === 'up').length} online
              </div>
            </div>
          )}
        </div>
      )}

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
              <th>In</th>
              <th>Out</th>
              <th>Packets In</th>
              <th>Packets Out</th>
              <th>Errors</th>
              <th>Dropped</th>
            </tr>
          </thead>
          <tbody>
            {data.interfaces.map((iface, i) => (
              <tr key={i}>
                <td className="text-lg">{statusIcon(iface.status)}</td>
                <td className="font-bold font-mono">{iface.name}</td>
                <td>{iface.description}</td>
                <td className="font-mono">{iface.ipv4 || '—'}</td>
                <td className="font-mono">{iface.ipv6 || '—'}</td>
                <td className="font-mono">{iface.mac || '—'}</td>
                <td className="font-mono">{iface.received_bytes ? formatBytes(iface.received_bytes) : '—'}</td>
                <td className="font-mono">{iface.sent_bytes ? formatBytes(iface.sent_bytes) : '—'}</td>
                <td className="font-mono">{iface.received_packets ? formatPackets(iface.received_packets) : '—'}</td>
                <td className="font-mono">{iface.sent_packets ? formatPackets(iface.sent_packets) : '—'}</td>
                <td className="font-mono">{iface.received_errors || iface.send_errors ? (iface.received_errors || 0) + (iface.send_errors || 0) : '0'}</td>
                <td className="font-mono">{iface.dropped_packets ? formatPackets(iface.dropped_packets) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>

      {/* Gateways */}
      {data.gateways.length > 0 && (
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
      )}

      {/* Services */}
      {data.services.length > 0 && (
        <div className="cyber-card p-4 scanlines">
          <h3 className="text-sm font-semibold text-cyber-textMuted uppercase tracking-wider mb-4">Services (top 10)</h3>
          <div className="cyber-table-responsive"><table className="cyber-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {data.services.map((svc, i) => (
                <tr key={i}>
                  <td className="text-lg">
                    {svc.status === 'running' ? '🟢' : '🔴'}
                  </td>
                  <td className="font-bold font-mono">{svc.name}</td>
                  <td>{svc.description}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </div>
      )}

      {/* Disconnected warning */}
      {isDisconnected && (
        <div className="cyber-card p-4 border-cyber-red/30">
          <div className="flex items-center gap-2">
            <span className="text-xl">⚠️</span>
            <div>
              <div className="font-bold text-cyber-red">OPNsense Disconnected</div>
              <div className="text-sm text-cyber-textMuted">
                Check OPNsense configuration in Settings tab. Verify OPN_HOST, OPN_API_KEY, and OPN_API_SECRET environment variables.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}