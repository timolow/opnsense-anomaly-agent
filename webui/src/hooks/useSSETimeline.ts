// useSSETimeline - Connect to SSE stream and update timeline data in real-time
import { useState, useEffect, useRef, useCallback } from 'react';

interface TimelinePoint {
  time: number; // Unix timestamp
  value: number;
}

interface SSEEvent {
  type: string;
  severity: string;
  src_ip: string;
  timestamp: string;
}

function useSSETimeline(initialData: TimelinePoint[]) {
  const [data, setData] = useState<TimelinePoint[]>(initialData);
  const eventSourceRef = useRef<EventSource | null>(null);
  const dataRef = useRef<TimelinePoint[]>(initialData);

  const handleSSEMessage = useCallback((event: MessageEvent) => {
    try {
      const message = JSON.parse(event.data);

      // Parse the timestamp and add to our timeline
      const timestamp = Math.floor(new Date(message.timestamp || Date.now()).getTime() / 1000);

      setData(prevData => {
        const newData = [...prevData];

        // Check if we already have a data point for this exact second
        const existingIndex = newData.findIndex(d => d.time === timestamp);

        if (existingIndex >= 0) {
          // Increment the count for this timestamp
          newData[existingIndex] = {
            ...newData[existingIndex],
            value: newData[existingIndex].value + 1,
          };
        } else {
          // Add a new data point
          newData.push({ time: timestamp, value: 1 });
          // Keep sorted by time
          newData.sort((a, b) => a.time - b.time);
        }

        // Trim to keep only recent data (last 1000 points)
        if (newData.length > 1000) {
          newData.splice(0, newData.length - 1000);
        }

        dataRef.current = newData;
        return newData;
      });
    } catch (error) {
      console.error('Failed to parse SSE message:', error);
    }
  }, []);

  useEffect(() => {
    // Connect to SSE endpoint
    eventSourceRef.current = new EventSource('/api/sse');

    eventSourceRef.current.onmessage = (event) => {
      handleSSEMessage(event);
    };

    eventSourceRef.current.onerror = (error) => {
      console.error('SSE connection error:', error);
      // EventSource will automatically reconnect
    };

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [handleSSEMessage]);

  return data;
}

export default useSSETimeline;