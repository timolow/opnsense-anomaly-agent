// ═══════════════════════════════════════════════════
// Type Definitions - OPNsense SOC Dashboard
// ═══════════════════════════════════════════════════

export interface SparklinePoint {
  time: string;
  count: number;
}

export interface SparklineData {
  events: SparklinePoint[];
  blocked: SparklinePoint[];
  passed: SparklinePoint[];
  unique_ips: SparklinePoint[];
  anomalies: SparklinePoint[];
}

export interface StatsData {
  total_events: number;
  events_24h: number;
  anomalies_detected: number;
  alerts_sent: number;
  rules_classified: number;
  mutes_active: number;
  blocked_24h: number;
  passed_24h: number;
  unique_ips: number;
  threat_critical: number;
  threat_high: number;
  threat_medium: number;
  threat_low: number;
  health: {
    postgres: string;
    redis: string;
    opnsense: string;
  };
  counters: Record<string, unknown>;
  sparklines?: SparklineData;
}

export interface HeatmapData {
  matrix: number[][];
  labels: string[];
  rowLabels: string[];
  ip: string[];
  hour: number[];
  value: number[];
}

export interface IpFlowData {
  nodes: Array<{
    id: string;
    label: string;
    category: string;
    color: string;
    size: number;
    count: number;
  }>;
  edges: Array<{
    source: string;
    target: string;
    value: number;
  }>;
}

// ── Clustered flow types ──
export interface IpFlowClusterNode {
  id: string;
  label: string;
  category: string;
  color: string;
  size: number;
  count: number;
  is_cluster: boolean;
  ip_count?: number;
}

export interface IpFlowClusterEdge {
  source: string;
  target: string;
  value: number;
}

export interface IpFlowClusterData {
  nodes: IpFlowClusterNode[];
  edges: IpFlowClusterEdge[];
  clusters: Record<string, { id: string; label: string; category: string; color: string; ip_count: number; event_count: number }>;
}

export interface EventsData {
  events: Array<{
    timestamp: string;
    action: string;
    protocol: string;
    src_ip: string;
    dst_ip: string;
    src_port?: number;
    dst_port?: number;
    rule_name: string;
    interface: string;
    direction?: string;
    severity: string;
    category: string;
  }>;
  total: number;
}

export interface MutesData {
  id: string;
  ip: string;
  duration: string;
  reason: string;
  created: string;
  expires: string;
}

export interface GeoHotspot {
  ip: string;
  src_ip: string;
  lat: number;
  lon: number;
  count: number;
  severity: string;
  country: string;
  country_name?: string;
  dst_ip?: string;
  unique_dst?: number;
  interface?: string;
  action?: string;
  attack_type?: string;
}

export interface GeoCountry {
  country: string;
  code: string;
  count: number;
  percentage: number;
  color: string;
  flag: string;
  lat: number;
  lon: number;
  zoom: number;
  bbox: [number, number, number, number];
  x: number;
  y: number;
}

export interface GeoData {
  countries: GeoCountry[];
  hotspots: GeoHotspot[];
  total_events: number;
}

export interface HealthData {
  postgres: { status: string; message: string };
  redis: { status: string; message: string };
  opnsense: { status: string; message: string };
  agent: { status: string; events_processed: number; uptime: number };
}

export interface AlertsData {
  anomalies: Array<{
    timestamp: string;
    type: string;
    severity: string;
    source_ip: string;
    destination_ip: string;
    details: string;
    category: string;
  }>;
}

export interface OpnsenseStatusData {
  version: string;
  hostname: string;
  uptime: string;
  cpu_usage: number;
  memory_usage: number;
  memory_total_gb: number;
  memory_used_gb: number;
  firewall_rules: number;
  services_total: number;
  services_running: number;
  interfaces: Array<{
    name: string;
    description: string;
    mac: string;
    ipv4: string;
    ipv6: string;
    status: string;
    bandwidth_in: string;
    bandwidth_out: string;
    status_icon: string;
    received_bytes?: number;
    sent_bytes?: number;
    received_packets?: number;
    sent_packets?: number;
    received_errors?: number;
    send_errors?: number;
    dropped_packets?: number;
  }>;
  gateways: Array<{
    name: string;
    gateway_ip: string;
    interface: string;
    delay: number;
    loss: number;
    status: string;
    upstream: boolean;
    vpn_gateway: boolean;
  }>;
  services: Array<{
    name: string;
    status: string;
    description: string;
  }>;
}

export interface ZenArmorData {
  summary: {
    total_events: number;
    policies_count: number;
    anomalies_detected: number;
    events_24h: number;
    data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
    empty_message?: string;
  };
  policies: Array<{
    id: string;
    name: string;
    category: string;
    status: string;
    action: string;
    description: string;
    events: number;
  }>;
  policies_meta?: {
    items: ZenArmorData['policies'];
    data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
    empty_message?: string;
  };
  events: Array<{
    timestamp: string;
    action: string;
    category: string;
    severity: string;
    source_ip: string;
    destination_ip: string;
    url: string;
    policy: string;
    details: string;
  }>;
  anomalies: Array<{
    type: string;
    count: number;
    severity: string;
    description: string;
    source_ip: string;
    timestamp: string;
  }>;
}

export interface IdsData {
  summary: {
    total_events: number;
    signatures: number;
    anomalies_detected: number;
    events_24h: number;
    data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
    empty_message?: string;
  };
  signatures: Array<{
    id: string;
    name: string;
    category: string;
    severity: string;
    description: string;
    triggered_count: number;
    last_triggered: string;
  }>;
  events: Array<{
    timestamp: string;
    signature_id: string;
    signature_name: string;
    category: string;
    severity: string;
    source_ip: string;
    destination_ip: string;
    details: string;
  }>;
  anomalies: Array<{
    type: string;
    count: number;
    severity: string;
    description: string;
    source_ip: string;
    timestamp: string;
  }>;
}

export interface ServiceStatusData {
  services: Array<{
    name: string;
    status: string;
    last_check: string;
    details: string;
    uptime: string;
  }>;
  alerts: Array<{
    service: string;
    message: string;
    severity: string;
    timestamp: string;
  }>;
  dhcp?: {
    status: string;
    leases: number;
    active_leases: number;
    status_icon: string;
    details: string;
  };
  unbound?: {
    status: string;
    cache_size: number;
    queries_total: number;
    queries_cached: number;
    status_icon: string;
    details: string;
  };
  ntp?: {
    status: string;
    server: string;
    offset: number;
    status_icon: string;
    details: string;
  };
  openvpn?: {
    status: string;
    connections: number;
    bytes_in: string;
    bytes_out: string;
    status_icon: string;
    details: string;
  };
  wireguard?: {
    status: string;
    connections: number;
    bytes_in: string;
    bytes_out: string;
    status_icon: string;
    details: string;
  };
}

export interface RulesClassifiedData {
  summary: {
    total: number;
    high_traffic: number;
    low_traffic: number;
    abusive: number;
    good: number;
    uncertain: number;
  };
  rules: Array<{
    uuid: string;
    short_id: string;
    name: string;
    description: string;
    source_net: string;
    destination_net: string;
    action: string;
    events_24h: number;
    classification: string;
    confidence: number;
    ml_label?: string;
    ml_reason?: string;
    feedback_count: number;
  }>;
  ml_stats: {
    events_processed: number;
    rules_trained: number;
    last_training: string;
    accuracy: number;
    self_learning_enabled?: boolean;
    portscan_threshold: number;
    bruteforce_threshold: number;
    sensitivity: string;
  };
}

export interface RuleFeedback {
  rule_name: string;
  label: string;
  reason: string;
  user_id: string;
}

// ── /Elasticsearch types ──
export interface Event {
  rule: {
    id: string;
    uuid: string;
  };
  event: {
    action: string;
    reason: string;
    created: string;
    dataset: string;
  };
  interface: {
    name: string;
  };
  network: {
    direction: string;
    type: string;
    protocol: string;
    iana_number: string;
  };
  source: {
    ip: string;
    port: number;
    geo?: {
      country_name: string;
      city: string;
    };
  };
  destination: {
    ip: string;
    port: number;
    geo?: {
      country_name: string;
      city: string;
    };
  };
  pf: {
    packet: {
      length: number;
    };
    tcp?: {
      flags: string;
      sequence_number: string;
    };
  };
  '@timestamp': string;
  _id?: string;
  _index?: string;
}

export interface Stats {
  indices: string[];
  total_documents: number;
  total_store_bytes: number;
  total_store_mb: number;
}

// ──  Dashboard visualization types ──
export interface TrafficFlow {
  flow: Array<{ source: string; target: string; value: number }>;
  time_range: string;
}

export interface ProtocolDistribution {
  protocols: Array<{ protocol: string; count: number; percent: number }>;
  total: number;
}

export interface ActionDistribution {
  actions: Array<{ action: string; count: number; percent: number }>;
  total: number;
}

export interface Timeline {
  timeline: Array<{ time: string; count: number }>;
  blocked_timeline: Array<{ time: string; count: number }>;
  period: string;
}

export interface BlockedIps {
  blocked_ips: Array<{ ip: string; count: number; unique_targets: number; unique_ports: number }>;
  total_blocked: number;
}

export interface TopPorts {
  ports: Array<{ port: number; name: string; count: number; unique_sources: number; block_count: number; percent: number }>;
  total: number;
}

export interface RuleHeatmap {
  heatmap: Array<{ rule: string; hourly: Array<{ time: string; count: number }> }>;
  rules: string[];
}

export interface DirectionDistribution {
  directions: Array<{ direction: string; count: number; percent: number }>;
  total: number;
}

export interface RuleActionBreakdown {
  rules: Array<{ name: string; pass: number; block: number; total: number }>;
}

// ═══════════════════════════════════════════════════
// Nginx monitoring types
// ═══════════════════════════════════════════════════

export interface NginxSummary {
  total_requests: number;
  by_method: Record<string, number>;
  by_status: Record<string, number>;
  status_ok: number;
  status_client_err: number;
  status_server_err: number;
  unique_ips: number;
  top_ips: Array<{ ip: string; requests: number }>;
  top_paths: Array<{ path: string; requests: number }>;
  not_found_404: number;
  anomalies_by_type: Record<string, Record<string, number>>;
  data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
  empty_message?: string;
}

export interface NginxAnomalyList {
  items: NginxAnomaly[];
  data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
  empty_message?: string;
}

export interface NginxAnomaly {
  timestamp: string;
  attack_type: string;
  severity: string;
  src_ip: string;
  path?: string;
  status_code?: number;
  description: string;
}

export interface NginxTopPath {
  path: string;
  requests: number;
  errors: number;
}

export interface NginxTimelinePoint {
  hour: string;
  requests: number;
}

// ═══════════════════════════════════════════════════
// Baseline deviation types
// ═══════════════════════════════════════════════════

export interface BaselineDeviation {
  rule: string;
  rule_name: string;
  current_rate: number;
  baseline_rate: number;
  deviation: number;
  max_per_hour: number;
  sample_count: number;
  severity: 'critical' | 'warning' | 'info';
  last_updated: string | null;
}

export interface BaselineDeviationsData {
  deviations: BaselineDeviation[];
  total_rules_with_baseline: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════
// What Changed / new-since types
// ═══════════════════════════════════════════════════

export interface WhatChangedData {
  since_ts: string | null;
  hours_since: number | null;
  new_events: number;
  new_anomalies: number;
  new_blocked: number;
  new_unique_ips: Array<{ ip: string; count: number }>;
  new_rule_matches: Array<{ rule: string; count: number; last_seen: string }>;
  new_baseline_breaches: Array<{ rule_name: string; current_rate: number; baseline_rate: number; deviation: number }>;
  first_time: boolean;
}

// ═══════════════════════════════════════════════════
// DNS Query monitoring types
// ═══════════════════════════════════════════════════

export interface DnsQueryData {
  queries: Array<{
    domain: string;
    client_ip: string;
    query_type: string;
    response_code: string;
    timestamp: string;
  }>;
  total: number;
  top_domains: Array<{ domain: string; count: number }>;
  top_clients: Array<{ client_ip: string; count: number }>;
  data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
  empty_message?: string;
}

// ═══════════════════════════════════════════════════
// Behavioral Overview types (ML-PIVOT)
// ═══════════════════════════════════════════════════

export type BehaviorLevel = 'benign' | 'suspicious' | 'hostile' | 'info';

export interface BehaviorProfile {
  ip: string;
  behavior_score: number;       // 0-100
  threat_level: BehaviorLevel;
  event_count_24h: number;
  unique_ports: number;
  blocked_count: number;
  passed_count: number;
  first_seen: string;
  last_seen: string;
  classification: string;       // GOOD | ABUSIVE | SUSPICIOUS | UNCERTAIN
  top_rules: Array<{ rule: string; count: number }>;
}

export interface BehaviorTimelinePoint {
  time: string;
  benign: number;
  suspicious: number;
  hostile: number;
  avg_score: number;
}

export interface BehaviorTimelineData {
  timeline: BehaviorTimelinePoint[];
}

export interface IncidentStats {
  active: number;
  escalated_24h: number;
  resolved_24h: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_type: Array<{ type: string; count: number }>;
  recent: Array<{
    id: string;
    type: string;
    severity: string;
    source_ip: string;
    description: string;
    timestamp: string;
    status: 'active' | 'escalated' | 'resolved';
  }>;
}

export interface BehaviorIpBreakdown {
  total: number;
  benign: number;
  suspicious: number;
  hostile: number;
}

export interface BehaviorOverviewData {
  active_ips_24h: number;
  ip_breakdown: BehaviorIpBreakdown;
  incident_stats: IncidentStats;
  top_threat_ips: Array<{ ip: string; score: number; level: BehaviorLevel; events: number }>;
  pipeline_health: {
    events_per_second: number;
    last_event: string;
    db_connected: boolean;
    anomaly_rate: number;
  };
  behavior_timeline: BehaviorTimelinePoint[];
  behavioral_changes: {
    new_suspicious_ips: Array<{ ip: string; score: number }>;
    escalated_incidents: Array<{ type: string; severity: string }>;
    resolved_threats: Array<{ type: string; timestamp: string }>;
  };
  traffic_flows: Array<{
    src_category: string;
    dst_category: string;
    behavior_level: BehaviorLevel;
    event_count: number;
  }>;
  data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
  empty_message?: string;
}

// ═══════════════════════════════════════════════════
// Threat Canvas types (P5-T1)
// ═══════════════════════════════════════════════════

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SignalSource = 'firewall' | 'nginx' | 'ids' | 'dns' | 'zenarmor' | 'wan_flap' | 'service' | 'baseline';

export interface TimelineEvent {
  timestamp: string;
  source: SignalSource;
  signal_type: string;
  severity: string;
  description: string;
}

// ═══════════════════════════════════════════════════
// IP Timeline types (P5-T4) — richer event from /api/ip-timeline
// ═══════════════════════════════════════════════════

export interface IpTimelineEvent {
  timestamp: string;
  source: SignalSource;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  action: string;           // 'block', 'pass', '404', 'request', 'signature', 'resolution', 'policy', etc.
  interface_name: string;
  severity: string;
  rule_name: string;
  description: string;
}

export interface IpTimelineSignal {
  timestamp: string;
  source: SignalSource;
  signal_type: string;
  severity: string;
  description: string;
}

export interface IpTimelineIncident {
  incident_id: string;
  severity: string;
  signal_count: number;
  sources: SignalSource[];
  phases: string[];
  first_seen: string;
  last_seen: string;
  description: string;
  narrative: string;
  is_active: boolean;
  auto_resolved: boolean;
}

export interface IpTimelineData {
  ip: string;
  range: string;
  range_seconds: number;
  events: IpTimelineEvent[];
  signals: IpTimelineSignal[];
  incidents: IpTimelineIncident[];
  hostname: string | null;
  profile_threat_level: string;
  profile_behavior_score: number;
  error?: string;
}

export interface ThreatCanvasIncident {
  incident_id: string;
  ip: string;
  src_hostname?: string;
  dst_hostname?: string;
  threat_level: ThreatLevel;
  behavior_score: number;        // 0-100 unified behavioral score
  signal_count: number;
  source_count: number;          // unique sources contributing signals
  sources: SignalSource[];
  signal_types: string[];
  phases: string[];              // ['recon', 'probe', 'attack', 'exploit']
  first_seen: string;
  last_seen: string;
  narrative: string;
  timeline: TimelineEvent[];     // chronological events for this IP
  is_active: boolean;
}

export interface RecommendedAction {
  incident_id: string;
  ip: string;
  action: 'block_ip' | 'add_watchlist' | 'investigate' | 'escalate' | 'suppress';
  priority: 'immediate' | 'high' | 'medium' | 'low';
  reason: string;
  command?: string;              // e.g., firewall rule hint
}

export interface ThreatCanvasData {
  incidents: ThreatCanvasIncident[];       // ranked by behavior_score DESC
  actions: RecommendedAction[];
  summary: {
    total_active: number;
    total_incidents: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    unique_ips: number;
    unique_sources: number;
    top_source: SignalSource;
    top_source_count: number;
  };
  data_source_status?: 'configured' | 'no_data' | 'not_configured' | 'error';
  empty_message?: string;
}
