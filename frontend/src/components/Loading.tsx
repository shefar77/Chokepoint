/** Loading is a hairline progress rule and one mono line. No spinners. */

export function Loading({ what = 'reading graph' }: { what?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="ticker" />
      <span>{what}…</span>
      <span className="loading-rule" />
    </div>
  );
}
