/** One statement and the next action. Never a shrug. */

import type { ReactNode } from 'react';

interface EmptyStateProps {
  statement: string;
  action?: ReactNode;
  detail?: string;
}

export function EmptyState({ statement, action, detail }: EmptyStateProps) {
  return (
    <div className="empty">
      <p className="empty-line">{statement}</p>
      {detail ? <p className="mono-sm">{detail}</p> : null}
      {action ? <div className="btn-row">{action}</div> : null}
    </div>
  );
}
