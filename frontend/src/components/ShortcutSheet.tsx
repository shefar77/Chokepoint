/** The `?` sheet. Escape or the close control dismisses it. */

import { useEffect } from 'react';

import { SHORTCUTS } from '../lib/hotkeys';
import { Button } from './Button';
import { Kbd } from './Kbd';

interface ShortcutSheetProps {
  open: boolean;
  onClose: () => void;
}

export function ShortcutSheet({ open, onClose }: ShortcutSheetProps) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="sheet-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="Keyboard shortcuts"
      onClick={onClose}
    >
      <div className="sheet" onClick={(event) => event.stopPropagation()}>
        <header className="panel-head">
          <span className="label">Keyboard</span>
          <div className="panel-head-right">
            <Button icon="x" small variant="quiet" onClick={onClose}>
              Close
            </Button>
          </div>
        </header>
        <div className="sheet-body">
          {SHORTCUTS.map((shortcut) => (
            <div key={shortcut.key} style={{ display: 'contents' }}>
              <Kbd>{shortcut.key}</Kbd>
              <span>{shortcut.description}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
