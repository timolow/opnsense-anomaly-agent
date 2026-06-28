// ═══════════════════════════════════════════════════
// Nginx Tab - Web Server Traffic Monitoring
// ═══════════════════════════════════════════════════

import React, { useState, useEffect } from 'react';
import { api } from '../../api';
import type { NginxSummary, NginxAnomaly, NginxAnomalyList } from '../../types';
import { CYBER, CHART, severityStyle, METHOD_COLORS } from '../../utils/colors';

// Severity style helper for nginx anomalies
function nginxSeverityStyle(sev: string) {
  const s = severityStyle(sev);
  return { bg: s.bg, text: s.color, glow: s.glow };
}

// Attack type icon mapping
const attackIcons: Record<string, string> = {
  PATH_TRAVERSAL: '⚠️',
  BRUTE_FORCE: '🔓',
  DDOS: '🌊',
  SCAN: '🔍',
  INVALID_UA: '🤖',
};

// ── Summary Card Component ──
function SummaryCard({ title, value, color, description }: { title: string; value: string | number; color: string; description?: string }) {
  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
      boxShadow: `0 0 20px ${color}15, inset 0 1px 0 rgba(255,255,255,0.05)`,
      display: 'flex',
      flexDirection: 'column',
      gap: '4px',
    }}>
      <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '1px', color: CYBER.textMuted }}>
        {title}
      </div>
      <div style={{ fontSize: '28px', fontWeight: '700', color, fontFamily: 'monospace' }}>
        {value}
      </div>
      {description && (
        <div style={{ fontSize: '11px', color: CYBER.textMuted, marginTop: '2px' }}>
          {description}
        </div>
      )}
    </div>
  );
}

// ── Status Code Chart ──
function StatusCodeChart({ by_status }: { by_status: Record<string, number> }) {
  const total = Object.values(by_status).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const sorted = Object.entries(by_status)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
    }}>
      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.textMuted, textTransform: 'uppercase', letterSpacing: '1px' }}>
        Response Codes
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {sorted.map(([code, count]) => {
          const pct = total > 0 ? (count / total) * 100 : 0;
          const isOk = Number(code) < 400;
          const isErr = Number(code) >= 400 && Number(code) < 500;
          const isServer = Number(code) >= 500;
          const color = isOk ? CYBER.green : isErr ? CYBER.orange : CYBER.red;
          
          return (
            <div key={code} style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                fontSize: '13px', fontFamily: 'monospace', color, minWidth: '50px',
              }}>
                {code}
              </div>
              <div style={{
                flex: 1, height: '8px', background: 'rgba(255,255,255,0.05)',
                borderRadius: '4px', overflow: 'hidden',
              }}>
                <div style={{
                  width: `${pct}%`, height: '100%',
                  background: `linear-gradient(90deg, ${color}80, ${color})`,
                  borderRadius: '4px',
                  transition: 'width 0.3s ease',
                }} />
              </div>
              <div style={{ fontSize: '12px', color: CYBER.textMuted, minWidth: '60px', textAlign: 'right', fontFamily: 'monospace' }}>
                {(count || 0).toLocaleString()} ({pct.toFixed(1)}%)
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Methods Distribution ──
function MethodChart({ by_method }: { by_method: Record<string, number> }) {
  const total = Object.values(by_method).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const sorted = Object.entries(by_method).sort((a, b) => b[1] - a[1]);
  const colors = METHOD_COLORS;

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
    }}>
      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.textMuted, textTransform: 'uppercase', letterSpacing: '1px' }}>
        HTTP Methods
      </h3>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {sorted.map(([method, count], i) => {
          const pct = total > 0 ? (count / total) * 100 : 0;
          const color = colors[i % colors.length];
          return (
            <div key={method} style={{
              background: `${color}15`,
              border: `1px solid ${color}40`,
              borderRadius: '6px',
              padding: '8px 14px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '2px',
              flex: '1 1 80px',
              minWidth: '80px',
            }}>
              <div style={{ fontSize: '12px', fontWeight: '700', color, fontFamily: 'monospace'
              }}>{method}</div>
              <div style={{ fontSize: '16px', fontWeight: '700', color, fontFamily: 'monospace' }}>
                {count || 0}
              </div>
              <div style={{ fontSize: '10px', color: CYBER.textMuted }}>{pct.toFixed(1)}%</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Top IPs Table ──
function TopIPsTable({ ips }: { ips: Array<{ ip: string; requests: number }> }) {
  if (ips.length === 0) return (
    <div style={{ color: CYBER.textMuted, textAlign: 'center', padding: '20px', fontSize: '13px' }}>
      No data yet — nginx events will populate here as traffic flows.
    </div>
  );

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
      overflowX: 'auto',
    }}>
      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.textMuted, textTransform: 'uppercase', letterSpacing: '1px' }}>
        Top Source IPs
      </h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(0,255,170,0.1)' }}>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>IP Address</th>
            <th style={{ padding: '8px', textAlign: 'right', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Requests</th>
          </tr>
        </thead>
        <tbody>
          {ips.slice(0, 10).map((item, i) => (
            <tr key={item.ip} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
              <td style={{ padding: '8px', fontFamily: 'monospace', color: CYBER.text }}>
                {item.ip}
              </td>
              <td style={{ padding: '8px', textAlign: 'right', fontFamily: 'monospace', color: CYBER.green }}>
                {(item.requests || 0).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Top Paths Table ──
function TopPathsTable({ paths }: { paths: Array<{ path: string; requests: number }> }) {
  if (paths.length === 0) return null;

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
      overflowX: 'auto',
    }}>
      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.textMuted, textTransform: 'uppercase', letterSpacing: '1px' }}>
        Top Requested Paths
      </h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(0,255,170,0.1)' }}>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Path</th>
            <th style={{ padding: '8px', textAlign: 'right', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Requests</th>
          </tr>
        </thead>
        <tbody>
          {paths.slice(0, 10).map((item) => (
            <tr key={item.path} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
              <td style={{ padding: '8px', fontFamily: 'monospace', color: CYBER.text }}>
                {item.path}
              </td>
              <td style={{ padding: '8px', textAlign: 'right', fontFamily: 'monospace', color: CYBER.green }}>
                {(item.requests || 0).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Anomalies Table ──
function AnomaliesTable({ anomalies }: { anomalies: NginxAnomaly[] }) {
  if (anomalies.length === 0) return (
    <div style={{ color: CYBER.textMuted, textAlign: 'center', padding: '20px', fontSize: '13px' }}>
      No nginx anomalies detected — traffic looks clean.
    </div>
  );

  return (
    <div style={{
      background: 'rgba(10, 15, 30, 0.7)',
      border: '1px solid rgba(0, 255, 170, 0.15)',
      borderRadius: '8px',
      padding: '16px',
      backdropFilter: 'blur(10px)',
      overflowX: 'auto',
    }}>
      <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.textMuted, textTransform: 'uppercase', letterSpacing: '1px' }}>
        Recent Anomalies
      </h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(0,255,170,0.1)' }}>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Time</th>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Type</th>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Severity</th>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Source IP</th>
            <th style={{ padding: '8px', textAlign: 'left', color: CYBER.textMuted, fontWeight: '600', fontSize: '11px' }}>Description</th>
          </tr>
        </thead>
        <tbody>
          {anomalies.slice(0, 20).map((a, i) => {
            const sev = nginxSeverityStyle(a.severity) || { bg: CYBER.panel, text: CYBER.textMuted, glow: 'transparent' };
            const icon = attackIcons[a.attack_type] || '🔔';
            return (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                <td style={{ padding: '8px', fontFamily: 'monospace', color: CYBER.textMuted }}>
                  {new Date(a.timestamp).toLocaleTimeString()}
                </td>
                <td style={{ padding: '8px', color: CYBER.text }}>
                  {icon} {a.attack_type}
                </td>
                <td style={{ padding: '8px' }}>
                  <span style={{
                    background: sev.bg,
                    color: sev.text,
                    border: `1px solid ${sev.text}30`,
                    borderRadius: '4px',
                    padding: '2px 8px',
                    fontSize: '11px',
                    fontWeight: '600',
                  }}>
                    {a.severity}
                  </span>
                </td>
                <td style={{ padding: '8px', fontFamily: 'monospace', color: CYBER.text, fontSize: '12px' }}>
                  {a.src_ip}
                </td>
                <td style={{ padding: '8px', color: CYBER.textMuted, fontSize: '11px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.description}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main NginxTab Component ──
import { NginxSkeleton } from '../../components/SkeletonLoaders';
import { TabQueryError, EmptyStateBanner } from '../../components/TabShell';

export const NginxTab: React.FC = () => {
  const [summary, setSummary] = useState<NginxSummary | null>(null);
  const [anomalyList, setAnomalyList] = useState<NginxAnomalyList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [summaryData, anomalyData] = await Promise.all([
          api.getNginxSummary(),
          api.getNginxAnomalies(),
        ]);
        setSummary(summaryData);
        setAnomalyList(anomalyData);
        setLoading(false);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load nginx data');
        setLoading(false);
      }
    };
    fetchData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <NginxSkeleton />;

  if (error) {
    return (
      <TabQueryError
        error={new Error(error)}
        isError={true}
        onRetry={() => { setLoading(true); setError(null); api.getNginxSummary().then(setSummary).catch(() => setError('Failed to reload')) }}
        tabName="Nginx Monitor"
      />
    );
  }

  const s = summary;
  const anomalies = anomalyList?.items || [];
  const anomalyStatus = anomalyList?.data_source_status;
  const anomalyMsg = anomalyList?.empty_message;
  if (!s) {
    return (
      <div style={{
        background: 'rgba(10, 15, 30, 0.7)',
        border: '1px solid rgba(0, 255, 170, 0.15)',
        borderRadius: '8px',
        padding: '40px',
        textAlign: 'center',
      }}>
        <div style={{ fontSize: '16px', color: CYBER.textMuted, marginBottom: '12px' }}>
          🟢 Nginx monitoring initialized
        </div>
        <div style={{ fontSize: '12px', color: CYBER.textMuted, maxWidth: '400px', margin: '0 auto' }}>
          No nginx events recorded yet. Once OPNsense nginx logs start flowing through the syslog pipeline,
          traffic data and anomaly detection will appear here in real-time.
        </div>
      </div>
    );
  }

  // When nginx is not configured, show only the banner — skip all zero-value cards/charts.
  const isNotConfigured = s.data_source_status === 'not_configured' || s.data_source_status === 'error';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Empty state banner */}
      <EmptyStateBanner status={s.data_source_status} message={s.empty_message} />

      {/* Only render data panels when nginx is actually configured */}
      {!isNotConfigured && (
        <>
      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
        <SummaryCard
          title="Total Requests"
          value={(s.total_requests || 0).toLocaleString()}
          color={CYBER.green}
          description="Last 24 hours"
        />
        <SummaryCard
          title="Unique IPs"
          value={(s.unique_ips || 0).toLocaleString()}
          color={CYBER.accent}
        />
        <SummaryCard
          title="Status OK"
          value={(s.status_ok || 0).toLocaleString()}
          color={CYBER.green}
          description={`${(s.total_requests || 0) > 0 ? (((s.status_ok || 0) / (s.total_requests || 1)) * 100).toFixed(1) : 0}% of total`}
        />
        <SummaryCard
          title="Client Errors"
          value={(s.status_client_err || 0).toLocaleString()}
          color={CYBER.orange}
          description="4xx responses"
        />
        <SummaryCard
          title="Server Errors"
          value={(s.status_server_err || 0).toLocaleString()}
          color={CYBER.red}
          description="5xx responses"
        />
        <SummaryCard
          title="404 Not Found"
          value={(s.not_found_404 || 0).toLocaleString()}
          color={CYBER.yellow}
          description="Potential scanning"
        />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '16px' }}>
        <MethodChart by_method={s.by_method || {}} />
        <StatusCodeChart by_status={s.by_status || {}} />
      </div>

      {/* Top IPs + Top Paths */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '16px' }}>
        <TopIPsTable ips={s.top_ips || []} />
        <TopPathsTable paths={s.top_paths || []} />
      </div>

      {/* Anomalies by Type */}
      {Object.keys(s.anomalies_by_type || {}).length > 0 && (
        <div style={{
          background: 'rgba(10, 15, 30, 0.7)',
          border: '1px solid rgba(255, 0, 64, 0.15)',
          borderRadius: '8px',
          padding: '16px',
          backdropFilter: 'blur(10px)',
        }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: '14px', color: CYBER.red, textTransform: 'uppercase', letterSpacing: '1px' }}>
            Detected Anomalies by Type
          </h3>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {Object.entries(s.anomalies_by_type).map(([type, severities]) => (
              <div key={type} style={{
                background: 'rgba(255, 0, 64, 0.1)',
                border: '1px solid rgba(255, 0, 64, 0.2)',
                borderRadius: '6px',
                padding: '8px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}>
                <div style={{ fontSize: '12px', fontWeight: '700', color: CYBER.red, fontFamily: 'monospace' }}>
                  {attackIcons[type] || '🔔'} {type}
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {Object.entries(severities).map(([sev, count]) => {
                    const c = nginxSeverityStyle(sev) || { text: CYBER.textMuted, glow: 'transparent' };
                    return (
                      <span key={sev} style={{
                        fontSize: '10px',
                        color: c.text,
                      }}>
                        {sev}: {count}
                      </span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Anomalies Table */}
      <AnomaliesTable anomalies={anomalies} />
        </>
      )}

      {/* Footer */}
      <div style={{
        textAlign: 'center',
        padding: '12px',
        fontSize: '11px',
        color: CYBER.textMuted,
      }}>
        Nginx monitoring tracks web requests, detects path traversal, brute force, DDoS, and scanner activity.
        Refreshes every 30s.
      </div>
    </div>
  );
};

export default NginxTab;
