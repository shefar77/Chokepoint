/** The debate: claim, challenge, outcome, exactly as the graph recorded it. */

import type { ChallengeModel, HypothesisModel } from '../../../api/types';
import { EmptyState } from '../../../components/EmptyState';
import { Icon } from '../../../components/icons';
import { Stamp, type StampTone } from '../../../components/Stamp';
import { ratio, stepLabel } from '../../../lib/format';

interface BlackboardTabProps {
  hypotheses: HypothesisModel[];
  challenges: ChallengeModel[];
  onSelectStep: (stepId: string) => void;
}

function statusTone(status: string): StampTone {
  if (status === 'falsified') return 'upheld';
  if (status === 'supported') return 'suppress';
  if (status === 'weakened') return 'schedule';
  return 'neutral';
}

export function BlackboardTab({ hypotheses, challenges, onSelectStep }: BlackboardTabProps) {
  if (hypotheses.length === 0) {
    return (
      <div className="pane-scroll">
        <EmptyState
          statement="The blackboard is empty."
          detail="The Scout posts falsifiable claims here and the Skeptic attacks them. Agents never see each other's text, only this."
        />
      </div>
    );
  }
  const upheld = challenges.filter((challenge) => challenge.outcome === 'upheld').length;

  return (
    <div className="pane-scroll">
      <p className="mono-sm">
        Skeptic upheld {upheld} of {challenges.length} challenge{challenges.length === 1 ? '' : 's'}.
      </p>
      <div className="debate">
        {hypotheses.map((hypothesis) => {
          const attacks = challenges.filter(
            (challenge) => challenge.hypothesis_id === hypothesis.id,
          );
          return (
            <div className="debate-row" key={hypothesis.id}>
              <div className="debate-card" data-side="claim">
                <div className="debate-card-head">
                  <span className="mono-sm">{hypothesis.id}</span>
                  <Stamp tone={statusTone(hypothesis.status)}>{hypothesis.status}</Stamp>
                  <span className="mono-sm">conf {ratio(hypothesis.confidence, 2)}</span>
                </div>
                <p style={{ margin: 0 }}>{hypothesis.claim}</p>
                <div className="scope-chips" style={{ marginTop: 4 }}>
                  {hypothesis.based_on_step_ids.map((stepId) => (
                    <button
                      type="button"
                      className="citation"
                      key={stepId}
                      onClick={() => onSelectStep(stepId)}
                    >
                      [{stepLabel(stepId)}]
                    </button>
                  ))}
                </div>
              </div>
              <div className="debate-arrow">
                <Icon name="arrow-right" size={14} />
              </div>
              <div>
                {attacks.length === 0 ? (
                  <div className="debate-empty">No challenge was raised against this claim.</div>
                ) : (
                  attacks.map((challenge) => (
                    <div className="debate-card" data-side="challenge" key={challenge.id}>
                      <div className="debate-card-head">
                        <span className="mono-sm">{challenge.kind}</span>
                        <Stamp tone={challenge.outcome === 'upheld' ? 'upheld' : 'rejected'}>
                          {challenge.outcome}
                        </Stamp>
                      </div>
                      <p style={{ margin: 0 }}>{challenge.claim}</p>
                      <div className="scope-chips" style={{ marginTop: 4 }}>
                        {challenge.based_on_step_ids.map((stepId) => (
                          <button
                            type="button"
                            className="citation"
                            key={stepId}
                            onClick={() => onSelectStep(stepId)}
                          >
                            [{stepLabel(stepId)}]
                          </button>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
