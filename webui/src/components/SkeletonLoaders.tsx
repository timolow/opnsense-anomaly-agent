// ═══════════════════════════════════════════════════
// Skeleton Loader Components - Per-tab loading states
// Dark cyberpunk skeleton UI primitives that mimic
// actual tab layout while data fetches.
// ═══════════════════════════════════════════════════

import React from 'react';

// ── Basic skeleton block ──
function SkeletonBlock({ className = '', style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div
      className={`animate-pulse bg-cyber-panel/60 rounded border border-cyber-border/30 ${className}`}
      style={style}
    />
  );
}

// ── Tab Header Skeleton (icon + title + subtitle) ──
export function TabHeaderSkeleton() {
  return (
    <div className="flex items-center gap-3 mb-4">
      <SkeletonBlock className="w-8 h-8 rounded-md flex-shrink-0" />
      <SkeletonBlock className="h-5 w-36" />
      <SkeletonBlock className="h-4 w-24 text-xs" />
    </div>
  );
}

// ── Stat Card Grid Skeleton ──
export function StatCardSkeleton({ count = 4, cols = 'lg:grid-cols-4' }: { count?: number; cols?: string }) {
  const gridCols = `grid grid-cols-1 sm:grid-cols-2 ${cols} gap-3`;
  return (
    <div className={gridCols}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonBlock key={i} className="h-20" />
      ))}
    </div>
  );
}

// ── Chart Container Skeleton ──
export function ChartSkeleton({ height = 250 }: { height?: number }) {
  return (
    <div className="cyber-card p-4">
      <SkeletonBlock className="h-4 w-40 mb-4" />
      <SkeletonBlock style={{ height }} />
    </div>
  );
}

// ── Table Skeleton ──
export function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="cyber-card p-4">
      {/* Header row */}
      <div className="flex gap-4 mb-3">
        <SkeletonBlock className="h-4 flex-1" />
        <SkeletonBlock className="h-4 flex-1" />
        <SkeletonBlock className="h-4 flex-1" />
        <SkeletonBlock className="h-4 flex-1 hidden sm:block" />
        <SkeletonBlock className="h-4 flex-1 hidden lg:block" />
      </div>
      {/* Data rows */}
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex gap-4">
            <SkeletonBlock className="h-4 flex-1" />
            <SkeletonBlock className="h-4 w-16 flex-shrink-0" />
            <SkeletonBlock className="h-4 flex-1" />
            <SkeletonBlock className="h-4 flex-1 hidden sm:block" />
            <SkeletonBlock className="h-4 flex-1 hidden lg:block" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Two Column Layout Skeleton ──
export function TwoColumnSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <SkeletonBlock className="h-64" />
      <SkeletonBlock className="h-64" />
    </div>
  );
}

// ── Filter Bar Skeleton ──
export function FilterBarSkeleton() {
  return (
    <div className="flex flex-col sm:flex-row gap-3 mb-4">
      <SkeletonBlock className="h-10 flex-1" />
      <SkeletonBlock className="h-10 w-32" />
      <SkeletonBlock className="h-10 w-32" />
    </div>
  );
}

// ── Form Skeleton ──
export function FormSkeleton({ fields = 4 }: { fields?: number }) {
  return (
    <div className="cyber-card p-4 space-y-4">
      {Array.from({ length: fields }).map((_, i) => (
        <div key={i} className="space-y-2">
          <SkeletonBlock className="h-3 w-24" />
          <SkeletonBlock className="h-10 w-full" />
        </div>
      ))}
      <div className="flex gap-3 pt-2">
        <SkeletonBlock className="h-10 w-28" />
        <SkeletonBlock className="h-10 w-28" />
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════
// Per-Tab Skeleton Components
// Each tab gets a skeleton that mimics its actual layout
// ═══════════════════════════════════════════════════

// ── OverviewTab Skeleton ──
// Layout: threat summary (4 small cards) → stat grid (8 cards) → timeline chart → top threats list
export function OverviewSkeleton() {
  return (
    <div className="space-y-6">
      <TabHeaderSkeleton />
      {/* Threat severity summary - 4 cards */}
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      {/* Stat boxes - 8 cards */}
      <StatCardSkeleton count={8} cols="lg:grid-cols-4" />
      {/* Timeline chart */}
      <ChartSkeleton height={300} />
      {/* Top threats / recent activity */}
      <TwoColumnSkeleton />
    </div>
  );
}

// ── AlertsTab Skeleton ──
// Layout: header → filter bar → alerts table
export function AlertsSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FilterBarSkeleton />
      <TableSkeleton rows={10} />
    </div>
  );
}

// ── HeatmapTab Skeleton ──
// Layout: header → canvas heatmap area
export function HeatmapSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <ChartSkeleton height={400} />
    </div>
  );
}

// ── FlowsTab Skeleton ──
// Layout: header → stat cards → flow list
export function FlowsSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── IpFlowTab Skeleton ──
// Layout: header → stat cards → IP flow table
export function IpFlowSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── MutesTab Skeleton ──
// Layout: header → search → mute list
export function MutesSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FilterBarSkeleton />
      <TableSkeleton rows={6} />
    </div>
  );
}

// ── ZenArmorTab Skeleton ──
// Layout: header → stat cards → threat table
export function ZenArmorSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── IdsTab Skeleton ──
// Layout: header → filter bar → IDS events table
export function IdsSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FilterBarSkeleton />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── GeoTab Skeleton ──
// Layout: header → two column (country bars + intensity grid)
export function GeoSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <TwoColumnSkeleton />
    </div>
  );
}

// ── OpnsenseTab Skeleton ──
// Layout: header → stat cards → service status list
export function OpnsenseSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={3} cols="lg:grid-cols-3" />
      <TableSkeleton rows={5} />
    </div>
  );
}

// ── RulesTab Skeleton ──
// Layout: header → filter bar → rules table
export function RulesSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FilterBarSkeleton />
      <TableSkeleton rows={10} />
    </div>
  );
}

// ── RulesClassifiedTab Skeleton ──
// Layout: header → stat cards → classified rules table
export function RulesClassifiedSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── SyslogsTab Skeleton ──
// Layout: header → syslog entries table
export function SyslogsSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <TableSkeleton rows={10} />
    </div>
  );
}

// ── ServicesTab Skeleton ──
// Layout: header → service status cards
export function ServicesSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={4} />
    </div>
  );
}

// ── SettingsTab Skeleton ──
// Layout: header → form fields
export function SettingsSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FormSkeleton fields={6} />
    </div>
  );
}

// ── LogsQueryTab Skeleton ──
// Layout: header → search form → results table
export function LogsQuerySkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <FormSkeleton fields={3} />
      <TableSkeleton rows={6} />
    </div>
  );
}

// ── NetworkTab Skeleton ──
// Layout: header → stat cards → force graph → charts
export function NetworkSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={5} cols="lg:grid-cols-5" />
      <ChartSkeleton height={450} />
      <TwoColumnSkeleton />
    </div>
  );
}

// ── WanFlapTab Skeleton ──
// Layout: header → stat cards → timeline chart → flap events table
export function WanFlapSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={3} cols="lg:grid-cols-3" />
      <ChartSkeleton height={250} />
      <TableSkeleton rows={5} />
    </div>
  );
}

// ── NginxTab Skeleton ──
// Layout: header → stat cards → anomaly table
export function NginxSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

export function DnsQueriesSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── NginxTab Skeleton ──
// Layout: header → stat cards → anomaly table
export function NginxSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <TableSkeleton rows={8} />
    </div>
  );
}

// ── Behavioral Overview Skeleton ──
export function BehavioralOverviewSkeleton() {
  return (
    <div className="space-y-6">
      <SkeletonBlock className="h-10" />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <SkeletonBlock className="h-24" />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <ChartSkeleton height={200} />
        </div>
        <SkeletonBlock style={{ height: 260 }} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SkeletonBlock style={{ height: 280 }} />
        <SkeletonBlock style={{ height: 280 }} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SkeletonBlock style={{ height: 200 }} />
        <SkeletonBlock style={{ height: 200 }} />
      </div>
    </div>
  );
}

// ── Skeleton dispatch by tab key ──
const SKELETON_MAP: Record<string, React.ComponentType> = {
  overview: OverviewSkeleton,
  heatmap: HeatmapSkeleton,
  flows: FlowsSkeleton,
  ipflow: IpFlowSkeleton,
  alerts: AlertsSkeleton,
  mutes: MutesSkeleton,
  zenarmor: ZenArmorSkeleton,
  ids: IdsSkeleton,
  geo: GeoSkeleton,
  opnsense: OpnsenseSkeleton,
  rules: RulesSkeleton,
  'rules-classified': RulesClassifiedSkeleton,
  syslogs: SyslogsSkeleton,
  services: ServicesSkeleton,
  settings: SettingsSkeleton,
  logs: DnsQueriesSkeleton,
  network: NetworkSkeleton,
  'wan-flap': WanFlapSkeleton,
  nginx: NginxSkeleton,
  'behavioral-overview': BehavioralOverviewSkeleton,
};

/**
 * Generic skeleton loader dispatched by tab key.
 * Falls back to a generic layout for unknown tabs.
 */
export function TabSkeleton({ tab }: { tab: string }) {
  const Skeleton = SKELETON_MAP[tab] || GenericSkeleton;
  return <Skeleton />;
}

// ── Generic fallback skeleton ──
function GenericSkeleton() {
  return (
    <div className="space-y-4">
      <TabHeaderSkeleton />
      <StatCardSkeleton count={4} cols="lg:grid-cols-4" />
      <ChartSkeleton height={250} />
      <TableSkeleton rows={5} />
    </div>
  );
}