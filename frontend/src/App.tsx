/** App shell: masthead, routed screen, footer, shortcut sheet. */

import { useEffect, useMemo } from 'react';
import { BrowserRouter } from 'react-router-dom';

import { Masthead } from './components/Masthead';
import { ShortcutSheet } from './components/ShortcutSheet';
import { useHotkeys } from './lib/hotkeys';
import { AppRoutes } from './router';
import { useUI } from './store/useUI';

const HEALTH_INTERVAL_MS = 20_000;

function Shell() {
  const health = useUI((state) => state.health);
  const healthError = useUI((state) => state.healthError);
  const loadHealth = useUI((state) => state.loadHealth);
  const shortcutsOpen = useUI((state) => state.shortcutsOpen);
  const toggleShortcuts = useUI((state) => state.toggleShortcuts);

  useEffect(() => {
    void loadHealth();
    const timer = window.setInterval(() => void loadHealth(), HEALTH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [loadHealth]);

  const hotkeys = useMemo(
    () => [
      { key: '?', description: 'Shortcuts', handler: () => toggleShortcuts(true) },
      { key: 'Esc', description: 'Close', handler: () => toggleShortcuts(false) },
    ],
    [toggleShortcuts],
  );
  useHotkeys(hotkeys);

  return (
    <div className="app">
      <Masthead health={health} />
      {healthError ? (
        <div className="footer" role="status">
          <span>{healthError}</span>
        </div>
      ) : null}
      <AppRoutes />
      <footer className="footer">
        <span>Synthetic estate. No real system is described here.</span>
        <span>
          Public CVE ids carry approximate real severity; ids beginning ACME- or SYN- are invented.
        </span>
        <span>Ground truth is planted and read from disk, never from the graph.</span>
        <button type="button" className="btn btn-small btn-quiet" onClick={() => toggleShortcuts(true)}>
          Keyboard
        </button>
      </footer>
      <ShortcutSheet open={shortcutsOpen} onClose={() => toggleShortcuts(false)} />
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  );
}
