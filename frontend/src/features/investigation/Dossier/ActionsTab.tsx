/** Actions: proposed tickets with graph-resolved routing and human approval. */

import { useState } from 'react';

import { api } from '../../../api/client';
import type { ActionModel } from '../../../api/types';
import { Button } from '../../../components/Button';
import { EmptyState } from '../../../components/EmptyState';
import { ErrorBlock } from '../../../components/ErrorBlock';
import { Markdown } from '../../../components/Markdown';
import { Stamp } from '../../../components/Stamp';

interface ActionsTabProps {
  actions: ActionModel[];
  onUpdated: (action: ActionModel, message: string) => void;
}

function statusTone(status: string) {
  if (status === 'executed') return 'suppress' as const;
  if (status === 'rejected') return 'rejected' as const;
  return 'schedule' as const;
}

export function ActionsTab({ actions, onUpdated }: ActionsTabProps) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (actions.length === 0) {
    return (
      <div className="pane-scroll">
        <EmptyState
          statement="No action has been proposed yet."
          detail="The Scribe proposes a ticket for each FIX NOW verdict and for the top chokepoint fix. Nothing is sent until you approve it."
        />
      </div>
    );
  }

  const decide = async (action: ActionModel, approve: boolean) => {
    setBusyId(action.id);
    setError(null);
    try {
      const response = approve
        ? await api.approveAction(action.id)
        : await api.rejectAction(action.id);
      onUpdated(response.action, response.message);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The decision could not be recorded.');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="pane-scroll">
      {error ? <ErrorBlock title="Action failed" message={error} /> : null}
      {actions.map((action) => (
        <article className="action" key={action.id}>
          <header className="action-head">
            <Stamp tone={statusTone(action.status)}>{action.status}</Stamp>
            <span className="mono-sm">{action.kind}</span>
            <span className="action-title">{action.title}</span>
          </header>
          <div className="action-routing">
            <span>{action.id}</span>
            <span>verdict {action.verdict_id}</span>
            <span>team {action.team || 'unrouted'}</span>
            <span>{action.slack_channel || 'no channel'}</span>
            <span>on call: {action.on_call.join(', ') || 'nobody listed'}</span>
            <span>findings: {action.finding_ids.join(', ') || '—'}</span>
          </div>
          <div className="action-body">
            <Markdown source={action.body_md} />
          </div>
          {action.delivery.length > 0 ? (
            <div className="action-routing">
              {action.delivery.map((line) => (
                <span key={line}>{line}</span>
              ))}
            </div>
          ) : null}
          <footer className="action-foot">
            {action.status === 'proposed' ? (
              <>
                <Button
                  variant="primary"
                  icon="check"
                  small
                  disabled={busyId === action.id}
                  onClick={() => void decide(action, true)}
                >
                  Approve
                </Button>
                <Button
                  variant="threat"
                  icon="x"
                  small
                  disabled={busyId === action.id}
                  onClick={() => void decide(action, false)}
                >
                  Reject
                </Button>
                <span className="mono-sm">
                  Approving writes the outbox files and routes to the owning team.
                </span>
              </>
            ) : action.outbox_path ? (
              <span className="mono-sm">outbox: {action.outbox_path}</span>
            ) : (
              <span className="mono-sm">Nothing was sent.</span>
            )}
          </footer>
        </article>
      ))}
    </div>
  );
}
