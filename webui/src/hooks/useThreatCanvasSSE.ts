// useThreatCanvasSSE - Connect to SSE stream and trigger threat canvas refetch on events
import { useEffect, useRef, useState, useCallback } from 'react';

interface SSEMessage {
  type?: string;
  attack_type?: string;
  severity?: string;
  src_ip?: string;
  incident_id?: string;
  ip?: string;
  timestamp?: string;
  status?: string;
  action?: string;
}

export type SSEConnectionState = 'connected' | 'connecting' | 'disconnected';

interface UseThreatCanvasSsereturn {
  /** Current SSE connection state */
  connectionState: SSEConnectionState;
  /** Whether SSE is currently connected (for live indicator) */
  isConnected: boolean;
  /** Type of the most recent incident event (new_incident, incident_updated, incident_resolved) */
  lastEventType: string | null;
}

/**
 * Connects to /api/sse and fires `onEvent` whenever a new anomaly/incident
 * event arrives. Used by ThreatCanvasTab to trigger a refetch of the canvas
 * data so the incident list stays current without relying solely on polling.
 *
 * Returns connection state for live indicator rendering.
 */
export function useThreatCanvasSSE(
  onEvent: (msg: SSEMessage) => void,
): UseThreatCanvasSsereturn {
  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;
  const esRef = useRef<EventSource | null>(null);

  const [connectionState, setConnectionState] = useState<SSEConnectionState>('connecting');
  const [lastEventType, setLastEventType] = useState<string | null>(null);

  const handleConnect = useCallback(() => setConnectionState('connected'), []);
  const handleDisconnect = useCallback(() => setConnectionState('disconnected'), []);

  useEffect(() => {
    // Skip if EventSource is unavailable (SSR guard)
    if (typeof EventSource === 'undefined') {
      setConnectionState('disconnected');
      return;
    }

    const es = new EventSource('/api/sse');
    esRef.current = es;
    setConnectionState('connecting');

    // Listen for the 'connected' event sent by the server on initial handshake
    es.addEventListener('connected', () => {
      handleConnect();
    });

    es.onmessage = (event: MessageEvent) => {
      try {
        const msg = JSON.parse(event.data) as SSEMessage;
        // Track the last event type for debugging/logging
        if (msg.type) {
          setLastEventType(msg.type);
        }
        onEventRef.current(msg);
      } catch {
        // Ignore parse errors on heartbeat comments
      }
    };

    es.onerror = () => {
      // EventSource auto-reconnects; mark as disconnected until reconnected
      handleDisconnect();
    };

    return () => {
      es.close();
      esRef.current = null;
      setConnectionState('disconnected');
    };
  }, [handleConnect, handleDisconnect]);

  return {
    connectionState,
    isConnected: connectionState === 'connected',
    lastEventType,
  };
}
