/** Cross-screen UI state: health polling, the shortcut sheet, the notice line. */

import { create } from 'zustand';

import { api } from '../api/client';
import type { HealthResponse } from '../api/types';

export interface Notice {
  tone: 'info' | 'warn' | 'bad';
  text: string;
}

interface UIState {
  health: HealthResponse | null;
  healthError: string | null;
  shortcutsOpen: boolean;
  notice: Notice | null;
  loadHealth: () => Promise<void>;
  toggleShortcuts: (open?: boolean) => void;
  setNotice: (notice: Notice | null) => void;
}

export const useUI = create<UIState>((set) => ({
  health: null,
  healthError: null,
  shortcutsOpen: false,
  notice: null,

  loadHealth: async () => {
    try {
      const health = await api.health();
      set({ health, healthError: null });
    } catch (error) {
      set({ healthError: error instanceof Error ? error.message : 'Health check failed.' });
    }
  },

  toggleShortcuts: (open) =>
    set((state) => ({ shortcutsOpen: open === undefined ? !state.shortcutsOpen : open })),
  setNotice: (notice) => set({ notice }),
}));
