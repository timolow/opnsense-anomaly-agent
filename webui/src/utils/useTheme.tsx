// ═══════════════════════════════════════════════════
// Theme Context + Hook — apply theme to <html> and
// persist to localStorage.
// ═══════════════════════════════════════════════════

import { createContext, useContext, useEffect, useState } from 'react';
import { ThemeName, THEMES, DEFAULT_THEME, getActiveTheme } from '@/utils/themes';

interface ThemeContextType {
  theme: ThemeName;
  setTheme: (t: ThemeName) => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: DEFAULT_THEME,
  setTheme: () => {},
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(() => getActiveTheme());

  useEffect(() => {
    const html = document.documentElement;
    html.setAttribute('data-theme', theme);
    // Update CSS custom properties directly so Tailwind cyber.* classes
    // get overridden by theme.
    const t = THEMES[theme];
    const root = html.style;
    root.setProperty('--theme-bg', t.bg);
    root.setProperty('--theme-bg-darker', t.bgDarker);
    root.setProperty('--theme-panel', t.panel);
    root.setProperty('--theme-panel-hover', t.panelHover);
    root.setProperty('--theme-border', t.border);
    root.setProperty('--theme-border-light', t.borderLight);
    root.setProperty('--theme-text', t.text);
    root.setProperty('--theme-text-muted', t.textMuted);
    root.setProperty('--theme-text-dim', t.textDim);
    root.setProperty('--theme-accent', t.accent);
    root.setProperty('--theme-accent-hover', t.accentHover);
    root.setProperty('--theme-secondary', t.secondary);
    root.setProperty('--theme-green', t.green);
    root.setProperty('--theme-yellow', t.yellow);
    root.setProperty('--theme-orange', t.orange);
    root.setProperty('--theme-red', t.red);
    root.setProperty('--theme-scrollbar-track', t.scrollbarTrack);
    root.setProperty('--theme-scrollbar-thumb', t.scrollbarThumb);
    root.setProperty('--theme-scrollbar-thumb-hover', t.scrollbarThumbHover);
  }, [theme]);

  const setTheme = (t: ThemeName) => {
    try {
      localStorage.setItem('dashboard-theme', t);
    } catch { /* quota */ }
    setThemeState(t);
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
