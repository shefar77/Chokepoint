/** Verdicts: stamp, headline, cited claims, grounding, and the override form. */

import { useState } from 'react';

import { api } from '../../../api/client';
import type { VerdictKind, VerdictModel } from '../../../api/types';
import { Button } from '../../../components/Button';
import { EmptyState } from '../../../components/EmptyState';
import { ErrorBlock } from '../../../components/ErrorBlock';
import { GroundingStamp, Stamp, VerdictStamp } from '../../../components/Stamp';
import { ratio, stepLabel } from '../../../lib/format';

const KINDS: VerdictKind[] = ['FIX_NOW', 'SCHEDULE', 'ACCEPT', 'SUPPRESS'];

interface VerdictsTabProps {
  verdicts: VerdictModel[];
  selectedId: string | null;
  activeCitation: string | null;
  onSelect: (id: string) => void;
  onCitation: (stepId: string | null) => void;
  onFeedbackSaved: (verdictId: string, message: string) => void;
}

export function VerdictsTab({
  verdicts,
  selectedId,
  activeCitation,
  onSelect,
  onCitation,
  onFeedbackSaved,
}: VerdictsTabProps) {
  const [openOverride, setOpenOverride] = useState<string | null>(null);
  const [newKind, setNewKind] = useState<VerdictKind>('ACCEPT');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (verdicts.length === 0) {
    return (
      <div className="pane-scroll">
        <EmptyState
          statement="The Scribe has not adjudicated anything yet."
          detail="Verdicts arrive in the last phase, each one grouped by cause and fix."
        />
      </div>
    );
  }

  const submit = async (verdictId: string, action: 'agree' | 'override') => {
    setBusy(true);
    setError(null);
    try {
      const response = await api.feedback(verdictId, {
        action,
        ...(action === 'override' ? { new_kind: newKind } : {}),
        note: note.trim(),
      });
      setOpenOverride(null);
      setNote('');
      onFeedbackSaved(verdictId, response.message);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not record that feedback.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="pane-scroll">
      {error ? <ErrorBlock title="Feedback failed" message={error} /> : null}
      {verdicts.map((verdict) => {
        const selected = verdict.id === selectedId;
        return (
          <article
            className="verdict"
            key={verdict.id}
            onClick={() => onSelect(verdict.id)}
            style={selected ? { borderColor: 'var(--structure)' } : undefined}
          >
            <header className="verdict-head">
              <VerdictStamp kind={verdict.kind} />
              <GroundingStamp grounded={verdict.grounded} />
              {verdict.safety_valve ? (
                <Stamp tone="upheld" title={verdict.safety_valve_reason}>
                  safety valve
                </Stamp>
              ) : null}
              <span className="mono-sm">confidence {ratio(verdict.confidence, 2)}</span>
              <span className="mono-sm">{verdict.id}</span>
            </header>

            <p className="verdict-headline">{verdict.headline || 'No headline claim was written.'}</p>

            <div className="mono-sm" style={{ marginBottom: 'var(--s-2)' }}>
              findings: {verdict.finding_ids.join(', ') || '—'}
              {verdict.services.length > 0 ? ` · services: ${verdict.services.join(', ')}` : ''}
            </div>

            <ol className="claims">
              {verdict.claims.map((claim, index) => (
                <li className="claim" key={claim.id} data-grounded={claim.grounded ? 'true' : 'false'}>
                  <span className="claim-index">{String(index + 1).padStart(2, '0')}</span>
                  <span>
                    {claim.text}
                    {claim.cites.map((stepId) => (
                      <button
                        type="button"
                        className="citation"
                        key={stepId}
                        data-active={activeCitation === stepId ? 'true' : undefined}
                        onMouseEnter={() => onCitation(stepId)}
                        onFocus={() => onCitation(stepId)}
                        onMouseLeave={() => onCitation(null)}
                        onBlur={() => onCitation(null)}
                        onClick={(event) => {
                          event.stopPropagation();
                          onCitation(stepId);
                        }}
                        title={`Highlight ${stepId} and the nodes it touched`}
                      >
                        [{stepLabel(stepId)}]
                      </button>
                    ))}
                    {claim.failures.length > 0 ? (
                      <div className="claim-failures">unverified: {claim.failures.join('; ')}</div>
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>

            {verdict.feedback ? (
              <div className="feedback-note">
                <span className="label">
                  {verdict.feedback.action === 'override' ? 'Overridden' : 'Agreed'}
                </span>{' '}
                by {verdict.feedback.by}
                {verdict.feedback.new_kind ? ` to ${verdict.feedback.new_kind}` : ''}.{' '}
                {verdict.feedback.note}
                {verdict.feedback.lesson_id ? (
                  <>
                    {' '}
                    <span className="chip">taught {verdict.feedback.lesson_id}</span>
                  </>
                ) : null}
              </div>
            ) : (
              <div className="verdict-actions">
                <Button
                  icon="check"
                  small
                  disabled={busy}
                  onClick={(event) => {
                    event.stopPropagation();
                    void submit(verdict.id, 'agree');
                  }}
                >
                  Agree
                </Button>
                <Button
                  icon="flag"
                  small
                  variant="threat"
                  disabled={busy}
                  onClick={(event) => {
                    event.stopPropagation();
                    setOpenOverride(openOverride === verdict.id ? null : verdict.id);
                  }}
                >
                  Override
                </Button>
                <span className="mono-sm">An override needs a reason and becomes a lesson.</span>
              </div>
            )}

            {openOverride === verdict.id ? (
              <div className="override-form" onClick={(event) => event.stopPropagation()}>
                <div className="override-kinds">
                  {KINDS.filter((kind) => kind !== verdict.kind).map((kind) => (
                    <button
                      key={kind}
                      type="button"
                      className="preset"
                      aria-pressed={newKind === kind}
                      onClick={() => setNewKind(kind)}
                      style={{ width: 'auto' }}
                    >
                      {kind.replace('_', ' ')}
                    </button>
                  ))}
                </div>
                <label className="field">
                  <span className="label">Why (required)</span>
                  <textarea
                    rows={3}
                    value={note}
                    placeholder="sandbox-eu has no call or role route to any production data store"
                    onChange={(event) => setNote(event.target.value)}
                  />
                </label>
                <div className="btn-row">
                  <Button
                    variant="primary"
                    small
                    icon="check"
                    disabled={busy || note.trim().length < 4}
                    onClick={() => void submit(verdict.id, 'override')}
                  >
                    Save override
                  </Button>
                  <Button small variant="quiet" icon="x" onClick={() => setOpenOverride(null)}>
                    Cancel
                  </Button>
                </div>
              </div>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}
