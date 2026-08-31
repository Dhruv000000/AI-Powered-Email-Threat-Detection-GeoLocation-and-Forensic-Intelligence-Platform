/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#0B1120',
        sidebar: '#111827',
        surface: {
          DEFAULT: '#151E2E',
          hover: '#1B263B',
          muted: '#0F172A',
          elevated: '#1E293B',
        },
        border: {
          DEFAULT: '#263244',
          subtle: '#1E293B',
          highlight: '#3B82F6',
        },
        primary: {
          DEFAULT: '#3B82F6',
          dark: '#2563EB',
          subtle: 'rgba(59, 130, 246, 0.12)',
        },
        threat: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#10B981',
          clean: '#06B6D4',
        },
        status: {
          active: '#EF4444',
          investigating: '#F59E0B',
          mitigated: '#10B981',
          closed: '#64748B',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': '0.6875rem',
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.3), 0 1px 2px -1px rgba(0, 0, 0, 0.2)',
        'elevated': '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -2px rgba(0, 0, 0, 0.3)',
      }
    },
  },
  plugins: [],
}
