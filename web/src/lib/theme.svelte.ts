/**
 * Theme: 'dark' | 'light'.
 * Initial value is set by an inline script in app.html before paint
 * to avoid flash. This module exposes a reactive accessor + setter.
 */
import { browser } from '$app/environment';

export type Theme = 'dark' | 'light';
const STORAGE_KEY = 'enclava-theme';

function readInitial(): Theme {
  if (!browser) return 'dark';
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'dark' || stored === 'light') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

let current = $state<Theme>(readInitial());

export const theme = {
  get value(): Theme {
    return current;
  },
  set(next: Theme) {
    current = next;
    if (browser) {
      localStorage.setItem(STORAGE_KEY, next);
      document.documentElement.setAttribute('data-theme', next);
    }
  },
  toggle() {
    this.set(current === 'dark' ? 'light' : 'dark');
  }
};
