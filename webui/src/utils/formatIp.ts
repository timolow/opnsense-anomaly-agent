// ═══════════════════════════════════════════════════
// IP + Hostname formatting utility
// Shows "203.0.113.42 (scanner.example.com)" when hostname
// is available, or "203.0.113.42" when it is not.
// ═══════════════════════════════════════════════════

/**
 * Format an IP address with its resolved hostname (if available).
 *
 * Examples:
 *   format_ip("203.0.113.42")                    → "203.0.113.42"
 *   format_ip("203.0.113.42", null)              → "203.0.113.42"
 *   format_ip("203.0.113.42", "")                → "203.0.113.42"
 *   format_ip("203.0.113.42", "scanner.example.com") → "203.0.113.42 (scanner.example.com)"
 */
export function format_ip(ip: string | undefined | null, hostname?: string | null): string {
  const addr = ip || '';
  if (!addr) return '';

  const h = hostname || '';
  if (h) {
    return `${addr} (${h})`;
  }
  return addr;
}
