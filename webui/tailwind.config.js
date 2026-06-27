/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{ts,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: 'var(--theme-bg)',
          darker: 'var(--theme-bg-darker)',
          panel: 'var(--theme-panel)',
          panelHover: 'var(--theme-panel-hover)',
          border: 'var(--theme-border)',
          borderLight: 'var(--theme-border-light)',
          accent: 'var(--theme-accent)',
          accentHover: 'var(--theme-accent-hover)',
          pink: 'var(--theme-secondary)',
          purple: 'var(--theme-secondary)',
          green: 'var(--theme-green)',
          yellow: 'var(--theme-yellow)',
          orange: 'var(--theme-orange)',
          red: 'var(--theme-red)',
          text: 'var(--theme-text)',
          textMuted: 'var(--theme-text-muted)',
          textDim: 'var(--theme-text-dim)',
        },
        neon: {
          cyan: 'var(--theme-accent)',
          green: 'var(--theme-green)',
          red: 'var(--theme-red)',
          pink: 'var(--theme-secondary)',
          yellow: 'var(--theme-yellow)',
          purple: 'var(--theme-secondary)',
          orange: 'var(--theme-orange)',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      },
      boxShadow: {
        'neon-cyan': '0 0 10px rgba(0,229,255,0.3), 0 0 20px rgba(0,229,255,0.15)',
        'neon-pink': '0 0 10px rgba(255,0,110,0.3), 0 0 20px rgba(255,0,110,0.15)',
        'neon-purple': '0 0 10px rgba(131,56,236,0.3), 0 0 20px rgba(131,56,236,0.15)',
        'neon-green': '0 0 10px rgba(0,255,136,0.3), 0 0 20px rgba(0,255,136,0.15)',
      },
      animation: {
        'pulse-neon': 'pulseNeon 2s ease-in-out infinite',
      },
      keyframes: {
        pulseNeon: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.6 },
        },
      },
      backdropBlur: {
        cyber: '20px',
        cyberHeavy: '40px',
      },
    },
  },
  plugins: [],
}
