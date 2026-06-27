// ═══════════════════════════════════════════════════
// API Client - Fetches from the dashboard server
// ═══════════════════════════════════════════════════

import { CYBER } from '@/utils/colors';
import type {
  StatsData, HeatmapData, IpFlowData, EventsData, MutesData,
  GeoData, HealthData, AlertsData, OpnsenseStatusData,
  ZenArmorData, IdsData, ServiceStatusData, RulesClassifiedData,
  Event, Stats, RuleFeedback,
  TrafficFlow, ProtocolDistribution, ActionDistribution,
  Timeline, BlockedIps, TopPorts, RuleHeatmap,
  DirectionDistribution, RuleActionBreakdown,
  NginxSummary, NginxAnomaly, NginxAnomalyList,
  IpFlowClusterData,
  BaselineDeviationsData,
  WhatChangedData,
} from './types';

const BASE = '/api';

// Demo mode: mask IPs with placeholders
const DEMO_MODE = false;

function maskIp(ip: string): string {
  if (ip === '0.0.0.0' || !ip) return ip;
  return DEMO_MODE ? '10.0.XXX.XXX' : ip;
}

function maskAllIps(obj: unknown): unknown {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(maskAllIps);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (typeof v === 'string' && /^[0-9a-fA-F.:]+$/.test(v) && v.includes('.')) {
      result[k] = maskIp(v);
    } else if (typeof v === 'string' && /^[0-9a-fA-F.:]+$/.test(v) && v.includes(':') && v.length > 5) {
      // IPv6
      result[k] = maskIp(v);
    } else {
      result[k] = maskAllIps(v);
    }
  }
  return result;
}

function maskApiResponse<T>(data: T): T {
  return DEMO_MODE ? maskAllIps(data) as T : data;
}

async function json<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Accept': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${path}: ${res.status} ${body}`);
  }
  return res.json() as Promise<T>;
}

// ── /Elasticsearch ──
const _BASE = import.meta.env.VITE__HOST
  ? `${import.meta.env.VITE__HOST}/_search`
  : null;

export async function fetchEvents(params: {
  query?: Record<string, unknown>;
  size?: number;
  sort?: string;
  hours?: number;
}): Promise<{ hits: Event[]; total: number }> {
  if (!_BASE) {
    return { hits: [], total: 0 };
  }

  const query = params.query || {
    bool: {
      should: [
        { term: { 'event.action': 'pass' } },
        { term: { 'event.action': 'block' } },
      ],
      minimum_should_match: 1,
    },
  };

  if (params.hours) {
    (query as any).bool.filter = [{
      range: {
        '@timestamp': {
          gte: `now-${params.hours}h`,
          lte: 'now',
        },
      },
    }];
  }

  const body = {
    query,
    size: params.size || 100,
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: true,
  };

  const res = await fetch(_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) return { hits: [], total: 0 };
  const data = await res.json();
  const hits = data.hits.hits.map((h: { _source: Event }) => h._source);
  return { hits, total: data.hits.total.value };
}

export async function fetchStats(): Promise<Stats | null> {
  if (!_BASE) return null;
  try {
    const res = await fetch(`${import.meta.env.VITE__HOST}/-firewall-*/_stats`);
    if (!res.ok) return null;
    const data = await res.json();
    const idxStats = data.indices;
    let totalDocs = 0;
    let totalStore = 0;
    for (const name in idxStats) {
      totalDocs += idxStats[name].total?.docs?.count || 0;
      totalStore += idxStats[name].store?.size_in_bytes || 0;
    }
    return {
      indices: Object.keys(idxStats),
      total_documents: totalDocs,
      total_store_bytes: totalStore,
      total_store_mb: Math.round(totalStore / (1024 * 1024) * 100) / 100,
    };
  } catch {
    return null;
  }
}

import type { SparklineData } from '@/types';

// ── Dashboard API ──
function mapStats(raw: unknown): StatsData {
  const r = raw as Record<string, unknown>;
  const counters = (r.counters as Record<string, unknown>) || {};
  const bySeverity = (r.by_severity as Record<string, unknown>) || {};
  return {
    total_events: (r.total_events as number) || (counters.events_processed as number) || 0,
    events_24h: (counters.events_processed as number) || 0,
    anomalies_detected: (counters.anomalies_detected as number) || 0,
    alerts_sent: (counters.alerts_sent as number) || 0,
    rules_classified: (r.rules_classified as number) || 0,
    mutes_active: (r.active_mutes as number) || 0,
    blocked_24h: (r.blocked_24h as number) || 0,
    passed_24h: (r.passed_24h as number) || 0,
    unique_ips: (r.unique_ips as number) || (r.ip_classifications as number) || 0,
    threat_critical: (bySeverity.CRITICAL as number) || 0,
    threat_high: (bySeverity.HIGH as number) || 0,
    threat_medium: (bySeverity.MEDIUM as number) || 0,
    threat_low: (bySeverity.LOW as number) || 0,
    health: { postgres: 'unknown', redis: 'unknown', opnsense: 'unknown' },
    counters: counters as Record<string, unknown>,
    sparklines: r.sparklines as SparklineData | undefined,
  };
}

export const api = {
  // Stats & Overview
  stats: async (): Promise<StatsData> => {
    const raw = await json('/stats');
    return mapStats(raw);
  },
  health: () => json<HealthData>('/health'),
  heartbeat: () => json<{ ok: boolean; timestamp: number; events_processed: number; anomalies_detected: number }>('heartbeat'),

  // Core data
  heatmap: async (): Promise<HeatmapData> => {
    const raw = await json<Record<string, unknown>>('/heatmap');
    const data = raw.data || [];
    const labels_x = raw.labels_x || [];
    const labels_y = raw.labels_y || [];
    const rows = Array.isArray(data) ? data : [];
    return {
      matrix: rows as any[],
      labels: labels_x as string[],
      rowLabels: labels_y as string[],
      ip: labels_y as string[],
      hour: labels_x as number[],
      value: rows.map((r: any) => typeof r === 'number' ? r : (r.value || 0)),
    };
  },
  ipFlow: async (): Promise<IpFlowData> => {
    const raw = await json<Record<string, unknown>>('/ip-flow');
    const nodes = raw.nodes || [];
    const links = raw.links || [];
    return {
      nodes: nodes as any[],
      edges: links as any[],
    };
  },
  ipFlowClusters: async (params?: { expand?: string; threshold?: number }): Promise<IpFlowClusterData> => {
    const qs = new URLSearchParams();
    if (params?.expand) qs.set('expand', params.expand);
    if (params?.threshold) qs.set('threshold', String(params.threshold));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    const raw = await json<Record<string, unknown>>(`/ip-flow-clusters${suffix}`);
    return {
      nodes: (raw.nodes || []) as any[],
      edges: (raw.edges || []) as any[],
      clusters: (raw.clusters || {}) as any,
    };
  },
  events: async (limit = 100, offset = 0): Promise<EventsData> => {
    const raw = await json<Array<unknown>>(`/events?limit=${limit}&offset=${offset}`);
    const events = raw.map((e: any) => ({
      timestamp: '',
      action: e.severity || 'UNKNOWN',
      protocol: 'ip',
      src_ip: e.ip || '0.0.0.0',
      dst_ip: '',
      src_port: 0,
      dst_port: 0,
      rule_name: e.attack_type || 'unknown',
      interface: e.interface || 'unknown',
      direction: 'inbound',
      severity: e.severity || 'MEDIUM',
      category: e.category || 'unknown',
    }));
    return { events, total: raw.length };
  },
  geo: async (): Promise<GeoData> => {
    const raw = await json<Record<string, unknown>>('/geo');
    // Backend now returns {total_events, regions: [...]}
    // Convert to {countries: [...], hotspots: [...]}
    const regions = (raw.regions as any[]) || (Array.isArray(raw) ? raw : []);
    const countries = regions.map((r: any) => ({
      country: r.country || r.label || 'Unknown',
      count: r.count || 0,
      color: r.color || CYBER.textMuted,
      flag: r.flag || r.code || '',
      x: r.lon || 0,
      y: r.lat || 0,
    }));
    // Derive hotspots from regions (each region → one hotspot marker)
    const hotspots: GeoHotspot[] = regions.map((r: any) => ({
      ip: r.country || 'region',
      src_ip: r.country || 'region',
      lat: r.lat ?? 0,
      lon: r.lon ?? 0,
      count: r.count || 0,
      severity: r.count > 100000 ? 'CRITICAL' : r.count > 50000 ? 'HIGH' : r.count > 10000 ? 'MEDIUM' : 'LOW',
      country: r.code || r.country || '--',
      country_name: r.country || 'Unknown',
    }));
    return { countries, hotspots };
  },
  alerts: async (): Promise<AlertsData> => {
      // Merge volume-based alerts from events with ML-detected anomalies
      const [rawAlerts, rawAnomalies] = await Promise.all([
        json<Array<unknown>>('/alerts'),
        json<Array<unknown>>('/anomalies'),
      ]);

      const anomalies: AlertsData['anomalies'] = [];

      // Volume-based alerts from /api/alerts
      rawAlerts.forEach((a: any) => {
        anomalies.push({
          timestamp: a.timestamp || '',
          type: a.attack_type || 'UNKNOWN',
          severity: a.severity || 'MEDIUM',
          source_ip: a.ip || '0.0.0.0',
          destination_ip: '',
          details: `Count: ${a.count || 0}`,
          category: a.attack_type || 'unknown',
        });
      });

      // ML-detected anomalies from /api/anomalies (PORT_SCAN, BRUTE_FORCE, etc.)
      rawAnomalies.forEach((a: any) => {
        anomalies.push({
          timestamp: a.timestamp || '',
          type: a.attack_type || a.type || 'UNKNOWN',
          severity: a.severity || 'MEDIUM',
          source_ip: a.src_ip || a.source_ip || '0.0.0.0',
          destination_ip: a.dst_ip || a.destination_ip || '',
          details: a.description || '',
          category: a.attack_type || a.type || 'unknown',
        });
      });

      // Sort by timestamp descending
      anomalies.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      return { anomalies };
    },

  // OPNsense
  opnsense: async (): Promise<OpnsenseStatusData> => {
    const raw = await json<Record<string, unknown>>('/opnsense');
    const interfaces = Array.isArray(raw.interfaces) ? raw.interfaces : [];
    const interfacesMapped = interfaces.map((i: any) => ({
      name: i.name || '',
      description: i.description || '',
      mac: i.mac || '',
      ipv4: i.ipv4 || '',
      ipv6: i.ipv6 || '',
      status: i.status || (raw.status === 'connected' ? 'up' : 'down'),
      bandwidth_in: i.received_bytes ? `${(i.received_bytes / (1024**3)).toFixed(1)} GB` : '',
      bandwidth_out: i.sent_bytes ? `${(i.sent_bytes / (1024**3)).toFixed(1)} GB` : '',
      status_icon: raw.status === 'connected' ? 'connected' : 'disconnected',
      received_bytes: typeof i.received_bytes === 'number' ? i.received_bytes : 0,
      sent_bytes: typeof i.sent_bytes === 'number' ? i.sent_bytes : 0,
      received_packets: typeof i.received_packets === 'number' ? i.received_packets : 0,
      sent_packets: typeof i.sent_packets === 'number' ? i.sent_packets : 0,
      received_errors: typeof i.received_errors === 'number' ? i.received_errors : 0,
      send_errors: typeof i.send_errors === 'number' ? i.send_errors : 0,
      dropped_packets: typeof i.dropped_packets === 'number' ? i.dropped_packets : 0,
    }));
    const gateways = Array.isArray(raw.gateways) ? raw.gateways : [];
    const gatewaysMapped = gateways.map((g: any) => ({
      name: g.name || '',
      gateway_ip: g.gateway_ip || '',
      interface: g.interface || '',
      delay: typeof g.delay === 'number' ? g.delay : 0,
      loss: typeof g.loss === 'number' ? g.loss : 0,
      status: g.status || 'unknown',
      upstream: !!g.upstream,
      vpn_gateway: !!g.vpn_gateway,
    }));
    return {
      version: (raw.opnsense_version as string) || 'unknown',
      hostname: (raw.hostname as string) || '',
      uptime: (raw.uptime as string) || '',
      cpu_usage: typeof raw.cpu_usage === 'number' ? raw.cpu_usage : 0,
      memory_usage: typeof raw.memory_usage === 'number' ? raw.memory_usage : 0,
      memory_total_gb: typeof raw.memory_total_gb === 'number' ? raw.memory_total_gb : 0,
      memory_used_gb: typeof raw.memory_used_gb === 'number' ? raw.memory_used_gb : 0,
      firewall_rules: typeof raw.firewall_rules === 'number' ? raw.firewall_rules : 0,
      services_total: typeof raw.services_total === 'number' ? raw.services_total : 0,
      services_running: typeof raw.services_running === 'number' ? raw.services_running : 0,
      interfaces: interfacesMapped,
      gateways: gatewaysMapped,
      services: Array.isArray(raw.services) ? raw.services.map((s: any) => ({
        name: s.name || '',
        status: s.status || 'unknown',
        description: s.description || '',
      })) : [],
    };
  },

  // ZenArmor
  zenarmorSummary: async (): Promise<ZenArmorData['summary']> => {
    const raw = await json<Record<string, unknown>>('/zenarmor-summary');
    return {
      total_events: (raw.total_events as number) || 0,
      policies_count: (raw.policies_count as number) || (raw.known_policies_count as number) || 0,
      anomalies_detected: (raw.anomalies_detected as number) || 0,
      events_24h: (raw.events_24h as number) || (raw.total_events as number) || 0,
    };
  },
  zenarmorPolicies: async (): Promise<ZenArmorData['policies']> => {
    const raw = await json<Record<string, unknown>>('/zenarmor-policies');
    // Handle both array (legacy) and {items: [...], data_source_status, empty_message} formats
    if (Array.isArray(raw)) return raw.map((p: any) => ({
      id: p.id || '',
      name: p.name || p.policy_name || '',
      category: p.category || '',
      status: p.status || 'active',
      action: p.action || '',
      description: p.description || '',
      events: p.events || p.total_events || 0,
    }));
    const items = (raw.items as Array<unknown>) || [];
    return items.map((p: any) => ({
      id: p.id || '',
      name: p.name || p.policy_name || '',
      category: p.category || '',
      status: p.status || 'active',
      action: p.action || '',
      description: p.description || '',
      events: p.events || p.total_events || 0,
    }));
  },
  zenarmorEvents: (limit = 100, offset = 0) =>
    json<ZenArmorData['events'][]>(`/zenarmor-events?limit=${limit}&offset=${offset}`),
  zenarmorAnomalies: async (): Promise<ZenArmorData['anomalies'][]> => {
    const raw = await json<Array<unknown>>('/zenarmor-anomalies');
    return Array.isArray(raw) ? raw.map((a: any) => ({
      type: a.type || 'unknown',
      count: a.count || 0,
      severity: a.severity || 'MEDIUM',
      description: a.description || '',
      source_ip: a.source_ip || '0.0.0.0',
      timestamp: a.timestamp || '',
    })) : [];
  },

  // IDS
  idsSummary: async (): Promise<IdsData['summary']> => {
    const raw = await json<Record<string, unknown>>('/ids-summary');
    return {
      total_events: (raw.total_events as number) || 0,
      signatures: (raw.signatures as number) || (raw.known_signatures_count as number) || 0,
      anomalies_detected: (raw.anomalies_detected as number) || 0,
      events_24h: (raw.events_24h as number) || (raw.total_events as number) || 0,
    };
  },
  idsSignatures: async (): Promise<IdsData['signatures'][]> => {
    const raw = await json<Array<unknown>>('/ids-signatures');
    return Array.isArray(raw) ? raw.map((s: any) => ({
      id: s.id || (s.signature || '').substring(0, 8),
      name: s.name || s.signature || 'unknown',
      category: s.category || s.classification || 'unknown',
      severity: s.severity || (s.priority !== undefined ? (s.priority <= 1 ? 'HIGH' : 'MEDIUM') : 'MEDIUM'),
      description: s.description || '',
      triggered_count: s.triggered_count || s.triggers || s.trigger_count || 0,
      last_triggered: s.last_triggered || s.last_seen || '',
    })) : [];
  },
  idsEvents: (limit = 100, offset = 0) =>
    json<IdsData['events'][]>(`/ids-events?limit=${limit}&offset=${offset}`),
  idsAnomalies: async (): Promise<IdsData['anomalies'][]> => {
    const raw = await json<Array<unknown>>('/ids-anomalies');
    return Array.isArray(raw) ? raw.map((a: any) => ({
      type: a.type || 'unknown',
      count: a.count || 0,
      severity: a.severity || 'MEDIUM',
      description: a.description || '',
      source_ip: a.source_ip || '0.0.0.0',
      timestamp: a.timestamp || '',
    })) : [];
  },

  // Services
  serviceStatus: async (): Promise<ServiceStatusData> => {
    const raw = await json<Record<string, unknown>>('/service-status');
    const services = raw.services || {};
    const servicesArray = Object.entries(services).map(([name, svc]) => {
      const s = svc as Record<string, unknown>;
      const lastSeen = s.last_seen || '';
      const monitored = s.monitored === true;
      const anomalyCount = s.anomaly_count || 0;
      return {
        name,
        status: monitored ? 'monitored' : 'unmonitored',
        last_check: lastSeen ? new Date(lastSeen).toLocaleString() : 'N/A',
        details: `Events: ${s.total_events || 0}, Anomalies: ${anomalyCount}`,
        uptime: '',
      };
    });
    const unboundSvc = services.unbound as Record<string, unknown> || {};
    const dhcpSvc = services.dhcp as Record<string, unknown> || {};
    const ntpSvc = services.ntp as Record<string, unknown> || {};
    return {
      services: servicesArray,
      alerts: [],
      unbound: {
        status: (unboundSvc.monitored === true) ? 'running' : 'stopped',
        cache_size: (unboundSvc.metrics?.cache_size as number) || 0,
        queries_total: (unboundSvc.total_events as number) || 0,
        queries_cached: 0,
        status_icon: (unboundSvc.monitored === true) ? 'running' : 'stopped',
        details: '',
      },
      dhcp: {
        status: (dhcpSvc.monitored === true) ? 'running' : 'stopped',
        leases: 0,
        active_leases: 0,
        status_icon: (dhcpSvc.monitored === true) ? 'running' : 'stopped',
        details: '',
      },
      ntp: {
        status: (ntpSvc.monitored === true) ? 'running' : 'stopped',
        server: 'default',
        offset: 0,
        status_icon: (ntpSvc.monitored === true) ? 'running' : 'stopped',
        details: '',
      },
    };
  },

  // Rules classified / ML
  rulesClassified: async (refresh = false): Promise<RulesClassifiedData> => {
    const raw = await json<Record<string, unknown>>(`/rules-classified${refresh ? '?refresh=true' : ''}`);
    const summaryData = raw.summary || {};
    // classified_rules is the flat array of all rules
    const allRules = (raw.classified_rules as any[]) || [];
    // Extract classification counts
    const byClassification = summaryData.by_classification || {};
    return {
      summary: {
        total: (raw.total_rules as number) || allRules.length,
        high_traffic: 0,
        low_traffic: 0,
        abusive: (byClassification.ABUSIVE as number) || 0,
        good: (byClassification.GOOD as number) || 0,
        uncertain: (byClassification.UNCERTAIN as number) || (byClassification.UNKNOWN as number) || 0,
      },
      rules: allRules.map((r: any) => ({
        uuid: r.rule_name || '',
        short_id: (r.rule_name || '').substring(0, 8),
        name: r.human_readable_name || r.rule_name || '',
        description: r.rule_description || r.human_readable_name || r.rule_name || '',
        source_net: r.source_address || r.source_net || '',
        destination_net: r.destination_address || r.destination_net || '',
        action: r.rule_action || r.action || '',
        events_24h: r.total_events || 0,
        classification: r.classification || 'UNCERTAIN',
        confidence: Math.round((r.confidence || 0) * 100),
        ml_label: r.classification || '',
        ml_reason: r.ml_reason || r.reason || '',
        feedback_count: 0,
      })),
      ml_stats: {
        events_processed: (summaryData.total_events as number) || 0,
        rules_trained: allRules.length,
        last_training: '',
        accuracy: 0,
        portscan_threshold: 0,
        bruteforce_threshold: 0,
        sensitivity: 'medium',
      },
    };
  },
  mlSummary: async (): Promise<RulesClassifiedData['ml_stats'] | null> => {
    const raw = await json<Record<string, unknown>>('/ml-summary');
    return {
      events_processed: raw.events_processed || 0,
      rules_trained: raw.rules_trained || 0,
      last_training: '',
      accuracy: 0,
      portscan_threshold: 0,
      bruteforce_threshold: 0,
      sensitivity: raw.sensitivity || 'medium',
    };
  },
  activeLearningQueue: async (): Promise<Array<{ id: string; rule: string; state: string }>> => {
    const raw = await json<Array<unknown>>('/active-learning-queue');
    return Array.isArray(raw) ? raw.map((q: any) => ({ id: q.id || '', rule: q.rule || '', state: q.state || '' })) : [];
  },

  // ── -style visualizations ──
  trafficFlow: () => json<TrafficFlow>('/traffic-flow'),
  protocolDistribution: () => json<ProtocolDistribution>('/protocols'),
  actionDistribution: () => json<ActionDistribution>('/actions'),
  timeline: (params?: { period?: string; granularity?: string; start?: number; end?: number }) => {
    const qs = new URLSearchParams();
    if (params?.period) qs.set('period', params.period);
    if (params?.granularity) qs.set('granularity', params.granularity);
    if (params?.start) qs.set('start', String(params.start));
    if (params?.end) qs.set('end', String(params.end));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return json<Timeline>(`/timeline${suffix}`);
  },
  blockedIps: () => json<BlockedIps>('/blocked-ips'),
  topPorts: () => json<TopPorts>('/top-ports'),
  ruleHeatmap: () => json<RuleHeatmap>('/rule-heatmap'),
  directionDistribution: () => json<DirectionDistribution>('/directions'),
  ruleActionBreakdown: () => json<RuleActionBreakdown>('/rule-actions'),

  // Mutes
  mutes: () => json<MutesData[]>('/mutes'),
  createMute: (data: { ip: string; duration: string; reason: string }) =>
    json<{ success: boolean }>(`/mutes?ip=${encodeURIComponent(data.ip)}&duration=${encodeURIComponent(data.duration)}&reason=${encodeURIComponent(data.reason)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
  deleteMute: (id: string) =>
    json<{ success: boolean }>(`/mutes/${id}`, { method: 'DELETE' }),

  // Feedback
  submitFeedback: (data: RuleFeedback) =>
    json<{ success: boolean }>('/rule-feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),

  // ── Nginx web server monitoring ──
  getNginxSummary: () => json<NginxSummary>('/nginx-summary'),
  getNginxAnomalies: () => json<NginxAnomalyList>('/nginx-anomalies'),
  getNginxTopPaths: () => json<any[]>('/nginx-top-paths'),
  getNginxTimeline: () => json<any[]>('/nginx-timeline'),

  // Baseline deviations
  baselineDeviations: () => json<BaselineDeviationsData>('/baseline-deviations'),

  // What Changed / new-since
  newSince: (timestamp: number) => json<WhatChangedData>(`/new-since?timestamp=${timestamp}`),
};
