// ═══════════════════════════════════════════════════
// API Client - Fetches from the dashboard server
// ═══════════════════════════════════════════════════

import type {
  StatsData, HeatmapData, IpFlowData, EventsData, MutesData,
  GeoData, HealthData, AlertsData, OpnsenseStatusData,
  ZenArmorData, IdsData, ServiceStatusData, RulesClassifiedData,
  PfelkEvent, PfelkStats, RuleFeedback,
} from './types';

const BASE = '/api';

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

// ── pfelk/Elasticsearch ──
const PFELK_BASE = import.meta.env.VITE_PFELK_HOST
  ? `${import.meta.env.VITE_PFELK_HOST}/_search`
  : null;

export async function fetchPfelkEvents(params: {
  query?: Record<string, unknown>;
  size?: number;
  sort?: string;
  hours?: number;
}): Promise<{ hits: PfelkEvent[]; total: number }> {
  if (!PFELK_BASE) {
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

  const res = await fetch(PFELK_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) return { hits: [], total: 0 };
  const data = await res.json();
  const hits = data.hits.hits.map((h: { _source: PfelkEvent }) => h._source);
  return { hits, total: data.hits.total.value };
}

export async function fetchPfelkStats(): Promise<PfelkStats | null> {
  if (!PFELK_BASE) return null;
  try {
    const res = await fetch(`${import.meta.env.VITE_PFELK_HOST}/pfelk-firewall-*/_stats`);
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
    rules_classified: 0,
    mutes_active: (r.active_mutes as number) || 0,
    blocked_24h: 0,
    passed_24h: 0,
    unique_ips: (r.unique_ips as number) || (r.ip_classifications as number) || 0,
    threat_critical: (bySeverity.CRITICAL as number) || 0,
    threat_high: (bySeverity.HIGH as number) || 0,
    threat_medium: (bySeverity.MEDIUM as number) || 0,
    threat_low: (bySeverity.LOW as number) || 0,
    health: { postgres: 'unknown', redis: 'unknown', opnsense: 'unknown' },
    counters: counters as Record<string, unknown>,
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
    const raw = await json<Array<unknown>>('/geo');
    return {
      countries: raw.map((c: any) => ({
        country: c.country || c.label || 'Unknown',
        count: c.count || 0,
        color: c.color || '#888',
        flag: c.flag || '',
        x: c.x || 0,
        y: c.y || 0,
      })),
    };
  },
  alerts: async (): Promise<AlertsData> => {
    const raw = await json<Array<unknown>>('/alerts');
    const anomalies = raw.map((a: any) => ({
      timestamp: '',
      type: a.attack_type || 'UNKNOWN',
      severity: a.severity || 'MEDIUM',
      source_ip: a.ip || '0.0.0.0',
      destination_ip: '',
      details: `Count: ${a.count || 0}`,
      category: a.attack_type || 'unknown',
    }));
    return { anomalies };
  },

  // OPNsense
  opnsense: () => json<OpnsenseStatusData>('/opnsense'),

  // ZenArmor
  zenarmorSummary: () => json<ZenArmorData['summary']>('/zenarmor-summary'),
  zenarmorPolicies: () => json<ZenArmorData['policies'][]>('/zenarmor-policies'),
  zenarmorEvents: (limit = 100, offset = 0) =>
    json<ZenArmorData['events'][]>(`/zenarmor-events?limit=${limit}&offset=${offset}`),
  zenarmorAnomalies: () => json<ZenArmorData['anomalies'][]>('/zenarmor-anomalies'),

  // IDS
  idsSummary: () => json<IdsData['summary']>('/ids-summary'),
  idsSignatures: () => json<IdsData['signatures'][]>('/ids-signatures'),
  idsEvents: (limit = 100, offset = 0) =>
    json<IdsData['events'][]>(`/ids-events?limit=${limit}&offset=${offset}`),
  idsAnomalies: () => json<IdsData['anomalies'][]>('/ids-anomalies'),

  // Services
  serviceStatus: () => json<ServiceStatusData>('/service-status'),

  // Rules classified / ML
  rulesClassified: (refresh = false) =>
    json<RulesClassifiedData>(`/rules-classified${refresh ? '?refresh=true' : ''}`),
  mlSummary: () => json<RulesClassifiedData['ml_stats'] | null>('/ml-summary'),
  activeLearningQueue: () => json<Array<{ id: string; rule: string; state: string }>>('/active-learning-queue'),

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
    json<{ success: boolean }>(`/feedback?rule_name=${encodeURIComponent(data.rule_name)}&label=${encodeURIComponent(data.label)}&reason=${encodeURIComponent(data.reason)}&user_id=${encodeURIComponent(data.user_id)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
};
