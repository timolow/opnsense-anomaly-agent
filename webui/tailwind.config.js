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
          dark: '#0a0e17',
          darker: '#060a12',
          panel: '#111827',
          panelHover: '#1a2332',
          border: '#1e293b',
          borderLight: '#2d3a4e',
          accent: '#00e5ff',
          accentHover: '#00b8d4',
          pink: '#ff006e',
          purple: '#8338ec',
          green: '#00ff88',
          yellow: '#ffbe0b',
          orange: '#ff7800',
          red: '#ff1744',
          text: '#e2e8f0',
          textMuted: '#64748b',
          textDim: '#3b4a5c',
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
