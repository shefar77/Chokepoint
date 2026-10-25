/** Big editorial numerals with a mono caption underneath. */

interface NumeralProps {
  value: string;
  caption: string;
  small?: boolean;
  tone?: 'ink' | 'threat' | 'safe' | 'structure';
}

const TONE: Record<string, string> = {
  ink: 'var(--ink)',
  threat: 'var(--threat)',
  safe: 'var(--safe)',
  structure: 'var(--structure)',
};

export function Numeral({ value, caption, small = false, tone = 'ink' }: NumeralProps) {
  return (
    <div className="headline-cell">
      <span className={small ? 'numeral-sm' : 'numeral'} style={{ color: TONE[tone] }}>
        {value}
      </span>
      <span className="numeral-caption">{caption}</span>
    </div>
  );
}
