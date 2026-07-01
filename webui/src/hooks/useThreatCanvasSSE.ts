// useThreatCanvasSSE - Connect to SSE stream and trigger threat canvas refetch on events
import { useEffect, useRef } from 'react';

interface SSEMessage {
  type?: string;
  attack_type?: string;
  severity?: string;
  src_ip?: string;
  incident_id?: string;
  ip?: string;
  timestamp?: string;
}

/**
 * Connects to /api/sse and fires `onEvent` whenever a new anomaly/incident
 * event arrives. Used by ThreatCanvasTab to trigger a refetch of the canvas
 * data so the incident list stays current without relying solely on polling.
 */
export function useThreatCanvasSSE(onEvent: (msg: SSEMessage) => void) {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    // Skip if EventSource is unavailable (SSR guard)
    if (typeof EventSource === 'undefined') return;

    const es = new EventSource('/api/sse');
    esRef.current = es;

    es.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data) as SSEMessage;
        onEventRef.current(msg);
      } catch {
        // Ignore parse errors on heartbeat comments
      }
    };

    es.onerror = () => {
      // EventSource auto-reconnects; no-op
    };

    return () => {
      es.close();
      esRef.current = null;
    };
  }, []);
}
