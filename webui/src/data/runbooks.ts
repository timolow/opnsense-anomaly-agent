// =================================================================
// Runbook / Suggested Actions for Alert Types
// =================================================================
// Each alert type maps to a set of actionable suggestions for the
// SOC operator.  Actions can be "inline" (trigger API calls through
// the frontend) or "instructional" (show a text blurb the operator
// can follow manually).
// =================================================================

import { api } from '@/api';

export type ActionKind = 'inline' | 'instruction';

export interface RunbookAction {
  /** Short label shown in the UI button */
  label: string;
  /** What happens when clicked */
  kind: ActionKind;
  /** Only for inline: callback that performs the action */
  execute?: (alert: any) => Promise<{ ok: boolean; message: string }>;
  /** Only for instruction: guidance text */
  instruction?: string;
  /** Priority: 0 = high-priority / most likely first step */
  priority?: number;
  /** Optional icon hint (emoji or short text) */
  icon?: string;
}

export interface RunbookEntry {
  /** One-sentence summary of what this alert type means */
  summary: string;
  /** Recommended actions, sorted by priority (lower = first) */
  actions: RunbookAction[];
  /** Optional escalation guidance */
  escalation?: string;
}

// ── Action factories ───────────────────────────────────────────────

async function blockIp(ip: string): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await fetch('/api/ip-actions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'block', ip, reason: 'Blocked from alert runbook' }),
    });
    if (res.ok) {
      return { ok: true, message: `Blocked ${ip} via OPNsense firewall` };
    }
    const body = await res.text();
    return { ok: false, message: `Block failed: ${body}` };
  } catch (e: any) {
    return { ok: false, message: `Block error: ${e.message}` };
  }
}

async function muteAlert(ip: string, attackType: string): Promise<{ ok: boolean; message: string }> {
  try {
    await api.createMute({
      ip,
      duration: '3600',
      reason: `Muted from alert: ${attackType}`,
    });
    return { ok: true, message: `Muted alerts for ${ip} (1h)` };
  } catch (e: any) {
    return { ok: false, message: `Mute error: ${e.message}` };
  }
}

function opnsenseLink(ruleOrIp: string): string {
  return `/api/opnsense-search?q=${encodeURIComponent(ruleOrIp)}`;
}

// ── Runbook mapping ────────────────────────────────────────────────
// Keys match alert.type values from the backend.

export const runbooks: Record<string, RunbookEntry> = {
  PORT_SCAN: {
    summary: 'A single source IP is scanning multiple ports or hosts — potential reconnaissance.',
    escalation: 'If scan hits critical services (SSH, RDP, DB), escalate to HIGH and block immediately.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Check Firewall Rules',
        kind: 'instruction',
        icon: '📋',
        priority: 1,
        instruction:
          'Verify that no inbound rules allow unsolicited connections from external sources to internal hosts. Check OPNsense > Firewall > Rules > WAN for any overly permissive PASS rules.',
      },
      {
        label: 'Investigate Target',
        kind: 'instruction',
        icon: '🔍',
        priority: 2,
        instruction:
          'Check what services are running on the destination IP and ports. Look for exposed admin panels or database ports in your firewall configuration.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'PORT_SCAN'),
      },
    ],
  },

  SYN_FLOOD: {
    summary: 'High rate of TCP SYN packets to a destination — possible DoS or resource exhaustion attack.',
    escalation: 'CRITICAL severity. If upstream services degrade, contact ISP and enable SYN cookies immediately.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Enable SYN Cookies',
        kind: 'instruction',
        icon: '🍪',
        priority: 1,
        instruction:
          'On FreeBSD/OPNsense, run: sysctl net.inet.tcp.syncookies=1\nThis enables SYN cookie protection against SYN floods. To make persistent, add to /boot/loader.conf: net.inet.tcp.syncookies=1',
      },
      {
        label: 'Contact ISP',
        kind: 'instruction',
        icon: '📞',
        priority: 2,
        instruction:
          'Report the flood to your upstream ISP for traffic scrubbing or blackhole routing. Provide source IPs and peak packet rate.',
      },
      {
        label: 'Check Upstream',
        kind: 'instruction',
        icon: '🌐',
        priority: 3,
        instruction:
          'Monitor WAN interface traffic in Realtime > Traffic Graph. Check if the flood is hitting your entire network or a single host.',
      },
    ],
  },

  BRUTE_FORCE: {
    summary: 'Repeated failed authentication attempts on an exposed service (SSH, RDP, FTP, etc.).',
    escalation: 'If attempts exceed 50/min, block immediately. Check if credentials have been compromised.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Enable Rate Limiting',
        kind: 'instruction',
        icon: '⏱️',
        priority: 1,
        instruction:
          'Add a firewall alias with the attacking IP and create a LIMIT rule before your existing PASS rules. Or install the PF Sense plugin for built-in rate limiting.',
      },
      {
        label: 'Check Accounts',
        kind: 'instruction',
        icon: '👤',
        priority: 2,
        instruction:
          'Review auth logs on the target service for successful logins after brute force. SSH: grep "Accepted" /var/log/auth.log. Check for unauthorized key additions or password changes.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'BRUTE_FORCE'),
      },
    ],
  },

  PROBE: {
    summary: 'Suspicious network probes detected (XMAS, NULL, FIN scans, or ICMP floods) — active reconnaissance.',
    escalation: 'Probes often precede attacks. If probe source is already in threat intelligence, block immediately.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Check Rules',
        kind: 'instruction',
        icon: '📋',
        priority: 1,
        instruction:
          'Ensure all unusual TCP flag combinations (XMAS, NULL) are blocked by default. Verify your default WAN policy is DENY and only explicitly allowed traffic passes.',
      },
      {
        label: 'Review IDS/IPS Signatures',
        kind: 'instruction',
        icon: '🛡️',
        priority: 2,
        instruction:
          'Check Snort/Suricata logs for correlated signatures. If running Zenarmor or similar, verify probe signatures are enabled and in blocking mode.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'PROBE'),
      },
    ],
  },

  GEO_ANOMALY: {
    summary: 'Traffic from a new or high-risk country detected in blocked events.',
    escalation: 'Cross-reference with threat intelligence feeds. Persistent traffic from high-risk regions warrants investigation.',
    actions: [
      {
        label: 'Check Geo Location',
        kind: 'instruction',
        icon: '🌍',
        priority: 0,
        instruction:
          'Look up the source IP on ipinfo.io or whois lookup. Verify the country code matches expectations. Check if the IP belongs to a known CDN, cloud provider, or proxy service.',
      },
      {
        label: 'Verify Expected Traffic',
        kind: 'instruction',
        icon: '✅',
        priority: 1,
        instruction:
          'Is traffic from this region expected? Check with business teams if new services are deployed that serve users from this country. If unexpected, consider geo-blocking.',
      },
      {
        label: 'Add to Watchlist',
        kind: 'instruction',
        icon: '📝',
        priority: 2,
        instruction:
          'Create a firewall alias for the country/subnet and monitor traffic volume. Use OPNsense > Firewall > Aliases > GeoIP to manage country-based blocking.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'GEO_ANOMALY'),
      },
    ],
  },

  VOLUME_SPIKE: {
    summary: 'Service or rule traffic volume significantly exceeds normal baseline — possible misconfiguration or attack.',
    escalation: 'If volume exceeds 10x baseline, investigate immediately. Could indicate data exfiltration or misconfigured service.',
    actions: [
      {
        label: 'Check Baseline',
        kind: 'instruction',
        icon: '📊',
        priority: 0,
        instruction:
          'Navigate to the Overview tab > Baseline Deviations panel. Compare current rate to historical baseline. Check if the spike correlates with a deployment or scheduled task.',
      },
      {
        label: 'Verify Rule',
        kind: 'instruction',
        icon: '🔧',
        priority: 1,
        instruction:
          'Check the specific firewall rule in OPNsense > Firewall > Rules. Verify the rule matches intended traffic and is not catching a misconfigured service or log loop.',
      },
      {
        label: 'Contact Service Owner',
        kind: 'instruction',
        icon: '👥',
        priority: 2,
        instruction:
          'Identify the service or host generating/receiving the spike and notify the owner. Ask if a change was recently deployed that could explain the volume increase.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip || 'volume', 'VOLUME_SPIKE'),
      },
    ],
  },

  // ── Nginx-specific alert types ──────────────────────────────────
  PATH_TRAVERSAL: {
    summary: 'Web server received a path traversal attempt (../ sequences) — potential directory listing or file disclosure.',
    escalation: 'If combined with successful responses, check for exposed sensitive files immediately.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Check Web Config',
        kind: 'instruction',
        icon: '📋',
        priority: 1,
        instruction:
          'Verify Nginx root and location blocks restrict access to intended directories. Ensure try_files and alias directives cannot be manipulated.',
      },
      {
        label: 'Review Access Logs',
        kind: 'instruction',
        icon: '📄',
        priority: 2,
        instruction:
          'Check /var/log/nginx/access.log for successful responses (200) to traversal attempts. A 200 response means the attack succeeded.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'PATH_TRAVERSAL'),
      },
    ],
  },

  SCAN: {
    summary: 'Web server scan or enumeration detected — automated tool probing endpoints.',
    escalation: 'If scanner targets admin endpoints, escalate immediately.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Check Exposed Endpoints',
        kind: 'instruction',
        icon: '🔍',
        priority: 1,
        instruction:
          'Verify no admin panels, debug endpoints, or API documentation is publicly accessible. Check for exposed .git directories, server-status pages, or backup files.',
      },
      {
        label: 'Review User Agent',
        kind: 'instruction',
        icon: '🤖',
        priority: 2,
        instruction:
          'Identify the scanning tool from the User-Agent header. Common scanners: Nikto, Nmap, DirBuster, Gobuster. Block known scanner User-Agents in Nginx if appropriate.',
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'SCAN'),
      },
    ],
  },

  DDOS: {
    summary: 'DDoS pattern detected on web server — high request rate from a single source.',
    escalation: 'CRITICAL. If web services degrade, enable CDN protection and contact ISP for upstream filtering.',
    actions: [
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 0,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Enable Rate Limiting',
        kind: 'instruction',
        icon: '⏱️',
        priority: 1,
        instruction:
          'Add Nginx rate limiting: limit_req_zone $binary_remote_addr zone=anti_ddos:10m rate=10r/s; Apply to server/location blocks. Also add fail2ban rules for persistent offenders.',
      },
      {
        label: 'Enable CDN Protection',
        kind: 'instruction',
        icon: '🛡️',
        priority: 2,
        instruction:
          'If using Cloudflare or similar, enable Under Attack Mode and increase security level. Enable bot management and WAF rules for volumetric attacks.',
      },
      {
        label: 'Contact ISP',
        kind: 'instruction',
        icon: '📞',
        priority: 3,
        instruction:
          'For volumetric attacks exceeding your bandwidth, request ISP scrubbing or blackhole routing to protect downstream services.',
      },
    ],
  },

  INVALID_UA: {
    summary: 'Request with missing or suspicious User-Agent header — possible automated bot or misconfigured client.',
    escalation: 'Low severity unless combined with other indicators. Review access patterns for the source IP.',
    actions: [
      {
        label: 'Check Source IP',
        kind: 'instruction',
        icon: '🔍',
        priority: 0,
        instruction:
          'Look up the source IP reputation. Check if it belongs to a known bot, crawler, or malicious actor. Use the IP drill-down panel for enrichment details.',
      },
      {
        label: 'Review Request Pattern',
        kind: 'instruction',
        icon: '📊',
        priority: 1,
        instruction:
          'Check access logs for the source IP. High request rates with no User-Agent typically indicate a misconfigured scraper or early-stage scanning.',
      },
      {
        label: 'Block Source IP',
        kind: 'inline',
        icon: '🚫',
        priority: 2,
        execute: (alert) => blockIp(alert.source_ip),
      },
      {
        label: 'Mute Alert (1h)',
        kind: 'inline',
        icon: '🔇',
        priority: 3,
        execute: (alert) => muteAlert(alert.source_ip, 'INVALID_UA'),
      },
    ],
  },
};

// ── Fallback runbook for unknown alert types ──────────────────────

export const DEFAULT_RUNBOOK: RunbookEntry = {
  summary: 'An anomaly has been detected that does not match a known pattern.',
  escalation: 'Review alert details and correlate with other events before taking action.',
  actions: [
    {
      label: 'Investigate Source IP',
      kind: 'instruction',
      icon: '🔍',
      priority: 0,
      instruction:
        'Look up the source IP using the IP drill-down panel. Check geo-location, threat score, and recent event history.',
    },
    {
      label: 'Block Source IP',
      kind: 'inline',
      icon: '🚫',
      priority: 1,
      execute: (alert) => blockIp(alert.source_ip),
    },
    {
      label: 'Check Correlated Events',
      kind: 'instruction',
      icon: '🔗',
      priority: 2,
      instruction:
        'Navigate to the Syslogs tab and filter by the source IP. Look for related events within the same time window that provide context.',
    },
    {
      label: 'Mute Alert (1h)',
      kind: 'inline',
      icon: '🔇',
      priority: 3,
      execute: (alert) => muteAlert(alert.source_ip || 'unknown', alert.attack_type || 'UNKNOWN'),
    },
  ],
};

// ── Helpers ────────────────────────────────────────────────────────

/** Get the runbook for a given alert type (falls back to default). */
export function getRunbook(alertType: string): RunbookEntry {
  return runbooks[alertType] || DEFAULT_RUNBOOK;
}

/** Normalize alert type string to match runbook keys. */
export function normalizeAlertType(raw: string): string {
  const upper = raw.toUpperCase();
  // Handle underscores vs spaces, lowercase input, etc.
  const normalized = upper.replace(/\s+/g, '_');

  // Direct match
  if (runbooks[normalized]) return normalized;

  // Fuzzy match: check if any known type is a substring
  for (const key of Object.keys(runbooks)) {
    if (normalized.includes(key) || key.includes(normalized)) {
      return key;
    }
  }

  return normalized;
}