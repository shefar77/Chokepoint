/** EventSource subscription for the investigation stream. */

import type { StreamEvent } from './types';
import { API_BASE } from './client';

export interface StreamHandle {
  close: () => void;
}

export function subscribe(
  investigationId: string,
  onEvent: (event: StreamEvent) => void,
  onError?: (message: string) => void,
): StreamHandle {
  const source = new EventSource(`${API_BASE}/investigations/${investigationId}/stream`);
  let closed = false;

  const handle = (raw: MessageEvent<string>) => {
    try {
      onEvent(JSON.parse(raw.data) as StreamEvent);
    } catch {
      // Ignore non-json comments or heartbeat frames
    }
  };

  // The backend names each event after its type, and also sends the default
  // `message` event for clients that do not register named listeners.
  source.onmessage = handle;
  const types = [
    'run_started',
    'phase',
    'agent_message',
    'tool_call',
    'tool_result',
    'graph_highlight',
    'path_found',
    'hypothesis',
    'challenge',
    'memory_hit',
    'verdict',
    'action_proposed',
    'error',
    'run_finished',
  ];
  for (const type of types) {
    source.addEventListener(type, handle as EventListener);
  }

  source.onerror = () => {
    if (closed) return;
    if (source.readyState === EventSource.CLOSED) {
      onError?.('The event stream closed. Reload to replay this investigation.');
    }
  };

  return {
    close: () => {
      closed = true;
      source.close();
    },
  };
}
