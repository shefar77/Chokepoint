/** Entity: the properties and one-hop neighbourhood of the selected node. */

import { useEffect, useState } from 'react';

import { api } from '../../../api/client';
import type { GraphEdge, GraphNode } from '../../../api/types';
import { EmptyState } from '../../../components/EmptyState';
import { ErrorBlock } from '../../../components/ErrorBlock';
import { Loading } from '../../../components/Loading';
import { MiniGlyph } from '../../../components/Legend';
import { titleCase } from '../../../lib/format';

interface EntityTabProps {
  nodeId: string | null;
}

interface Neighbourhood {
  node: GraphNode | null;
  neighbours: { edge: GraphEdge; other: GraphNode; direction: 'out' | 'in' }[];
}

function describe(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (Array.isArray(value)) return value.map((item) => String(item)).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export function EntityTab({ nodeId }: EntityTabProps) {
  const [data, setData] = useState<Neighbourhood | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId) {
      setData(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .subgraph([nodeId], 1)
      .then((response) => {
        if (cancelled) return;
        const node = response.nodes.find((candidate) => candidate.id === nodeId) ?? null;
        const byId = new Map(response.nodes.map((candidate) => [candidate.id, candidate]));
        const neighbours: Neighbourhood['neighbours'] = [];
        for (const edge of response.edges) {
          if (edge.source === nodeId) {
            const other = byId.get(edge.target);
            if (other) neighbours.push({ edge, other, direction: 'out' });
          } else if (edge.target === nodeId) {
            const other = byId.get(edge.source);
            if (other) neighbours.push({ edge, other, direction: 'in' });
          }
        }
        setData({ node, neighbours });
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : 'Could not read that node.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [nodeId]);

  if (!nodeId) {
    return (
      <div className="pane-scroll">
        <EmptyState
          statement="No entity selected."
          detail="Click a node on the map, or a node chip in a ledger row, to open it here."
        />
      </div>
    );
  }
  if (error) {
    return (
      <div className="pane-scroll">
        <ErrorBlock title="Entity unavailable" message={error} />
      </div>
    );
  }
  if (loading || !data) {
    return (
      <div className="pane-scroll">
        <Loading what="reading node" />
      </div>
    );
  }
  if (!data.node) {
    return (
      <div className="pane-scroll">
        <EmptyState statement={`No node with id ${nodeId}.`} />
      </div>
    );
  }

  const node = data.node;
  const entries = Object.entries(node.props).filter(([key]) => key !== 'created_at');

  return (
    <div className="pane-scroll">
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-2)' }}>
        <MiniGlyph label={node.label} props={node.props} size={18} />
        <span className="statement" style={{ fontSize: 'var(--fs-16)' }}>
          {String(node.props.name ?? node.id)}
        </span>
        <span className="chip">{node.label}</span>
      </div>
      <p className="mono-sm">{node.id}</p>

      <span className="label">Properties</span>
      <div className="breakdown" style={{ gridTemplateColumns: 'minmax(0, 1fr) auto' }}>
        {entries.map(([key, value]) => (
          <div key={key} style={{ display: 'contents' }}>
            <span className="breakdown-key">{titleCase(key)}</span>
            <span className="breakdown-value">{describe(value)}</span>
          </div>
        ))}
      </div>

      <span className="label">One hop</span>
      {data.neighbours.length === 0 ? (
        <p className="mono-sm">Nothing connects to this node.</p>
      ) : (
        <ul className="checklist">
          {data.neighbours.slice(0, 40).map(({ edge, other, direction }) => (
            <li className="check" key={edge.id}>
              <MiniGlyph label={other.label} props={other.props} size={13} />
              <span>
                <span className="mono-sm">
                  {direction === 'out' ? '→' : '←'} {edge.type}
                </span>{' '}
                {other.id}
                {Object.keys(edge.props).length > 0 ? (
                  <div className="check-reason">
                    {Object.entries(edge.props)
                      .map(([key, value]) => `${key}=${describe(value)}`)
                      .join(' · ')}
                  </div>
                ) : null}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
