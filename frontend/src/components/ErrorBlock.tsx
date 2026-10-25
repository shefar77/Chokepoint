/** A bordered block naming the failing step and offering a retry. */

import { Button } from './Button';

interface ErrorBlockProps {
  title?: string;
  message: string;
  stepId?: string;
  onRetry?: () => void;
}

export function ErrorBlock({ title = 'Failed', message, stepId, onRetry }: ErrorBlockProps) {
  return (
    <div className="error-block" role="alert">
      <span className="label">{title}</span>
      {stepId ? <div className="mono-sm">step {stepId}</div> : null}
      <p className="error-detail">{message}</p>
      {onRetry ? (
        <Button icon="reset" small onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
