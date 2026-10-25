/** Mono status line: graph, MCP, agent mode, embeddings. */

import type { HealthResponse } from '../api/types';

type State = 'ok' | 'warn' | 'bad';

function Item({ state, children, title }: { state: State; children: string; title?: string }) {
  return (
    <span className="status-item" title={title}>
      <span className="status-dot" data-state={state} />
      {children}
    </span>
  );
}

export function StatusStrip({ health }: { health: HealthResponse | null }) {
  if (!health) {
    return (
      <div className="status-strip">
        <Item state="warn">reading status</Item>
      </div>
    );
  }
  const scripted = health.agent_mode !== 'live';
  const embeddings = health.embeddings.mode === 'fastembed' && !health.embeddings.warning;
  const algorithms = Object.values(health.capabilities.algorithms);
  const native = algorithms.filter((engine) => engine === 'networkx').length;
  return (
    <div className="status-strip">
      <Item
        state={health.graph_ok ? 'ok' : 'bad'}
        title={`graph ${health.graph} · ${health.node_count} nodes`}
      >
        {health.graph_ok ? `graph ok · ${health.node_count} nodes` : 'graph unreachable'}
      </Item>
      <Item state={health.mcp ? 'ok' : 'bad'} title={health.mcp_url}>
        {health.mcp ? `mcp ok · ${health.mcp_tools} tools` : 'mcp unreachable'}
      </Item>
      <Item
        state={scripted ? 'warn' : 'ok'}
        title={health.mode_warning || `model ${health.model}`}
      >
        {scripted ? 'scripted run' : `live · ${health.model}`}
      </Item>
      <Item
        state={embeddings ? 'ok' : 'warn'}
        title={health.embeddings.warning || health.embeddings.model}
      >
        {embeddings ? 'vector memory on' : 'vector memory off'}
      </Item>
      {algorithms.length > 0 ? (
        <Item
          state={native > 0 ? 'ok' : 'warn'}
          title={Object.entries(health.capabilities.algorithms)
            .map(([name, engine]) => `${name}: ${engine}`)
            .join(' · ')}
        >
          {`algo ${native}/${algorithms.length} native`}
        </Item>
      ) : null}
    </div>
  );
}
