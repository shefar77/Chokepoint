/** Start an investigation: a goal and four presets that match the demo script. */

import { useState } from 'react';

import { Button } from '../../components/Button';
import { ErrorBlock } from '../../components/ErrorBlock';
import { Panel } from '../../components/Panel';

export interface Preset {
  key: string;
  goal: string;
}

export const PRESETS: Preset[] = [
  { key: 'triage', goal: 'Triage the latest scan' },
  { key: 'target', goal: 'Is payments-vault reachable from the internet?' },
  { key: 'fixes', goal: 'What are the 3 fixes that matter most?' },
  { key: 'delta', goal: 'What changed since yesterday?' },
];

interface StartPanelProps {
  goal: string;
  preset: string;
  busy: boolean;
  error: string | null;
  onGoalChange: (goal: string) => void;
  onPresetChange: (preset: string, goal: string) => void;
  onStart: () => void;
}

export function StartPanel({
  goal,
  preset,
  busy,
  error,
  onGoalChange,
  onPresetChange,
  onStart,
}: StartPanelProps) {
  const [touched, setTouched] = useState(false);
  const tooShort = touched && goal.trim().length < 3;

  return (
    <Panel number="03" title="Start an investigation">
      <label className="field">
        <span className="label">Goal</span>
        <textarea
          rows={3}
          value={goal}
          placeholder="Triage the latest scan"
          onChange={(event) => {
            setTouched(true);
            onGoalChange(event.target.value);
          }}
        />
      </label>
      {tooShort ? <p className="mono-sm">A goal needs at least three characters.</p> : null}
      <div className="preset-row">
        {PRESETS.map((item, index) => (
          <button
            key={item.key}
            type="button"
            className="preset"
            aria-pressed={preset === item.key}
            onClick={() => onPresetChange(item.key, item.goal)}
          >
            <span className="preset-index">{String(index + 1).padStart(2, '0')}</span>
            {item.goal}
          </button>
        ))}
      </div>
      <div className="btn-row" style={{ marginTop: 'var(--s-3)' }}>
        <Button
          variant="primary"
          icon="play"
          disabled={busy || goal.trim().length < 3}
          onClick={onStart}
        >
          {busy ? 'Starting' : 'Run'}
        </Button>
        <span className="mono-sm" style={{ alignSelf: 'center' }}>
          Memory → Scout → Skeptic → Rebuttal → Scribe
        </span>
      </div>
      {error ? <ErrorBlock title="Could not start" message={error} /> : null}
    </Panel>
  );
}
