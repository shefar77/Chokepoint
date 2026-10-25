/** Keyboard shortcuts. Typing in a field never triggers one. */

import { useEffect } from 'react';

export interface Hotkey {
  key: string;
  description: string;
  handler: (event: KeyboardEvent) => void;
}

export const SHORTCUTS: { key: string; description: string }[] = [
  { key: 'g', description: 'Focus the graph' },
  { key: 'l', description: 'Focus the ledger' },
  { key: '/', description: 'Focus search' },
  { key: 'j', description: 'Next ledger row' },
  { key: 'k', description: 'Previous ledger row' },
  { key: 'Enter', description: 'Open the selected row' },
  { key: 'Esc', description: 'Clear highlight and selection' },
  { key: '?', description: 'Show this sheet' },
];

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || target.isContentEditable;
}

export function useHotkeys(hotkeys: Hotkey[], enabled = true): void {
  useEffect(() => {
    if (!enabled) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const key = event.key === 'Escape' ? 'Esc' : event.key;
      if (isTypingTarget(event.target) && key !== 'Esc') return;
      const match = hotkeys.find((hotkey) => hotkey.key === key);
      if (!match) return;
      event.preventDefault();
      match.handler(event);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [hotkeys, enabled]);
}
