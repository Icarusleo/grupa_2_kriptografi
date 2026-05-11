/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        node: {
          bg: '#2a3a2a',
          header: '#3a5a3a',
          border: '#4a7a4a',
          input: '#1a2a1a',
          output: '#1a2a1a',
        },
        handle: {
          data: '#9ca3af',
          key: '#60a5fa',
          cipher: '#f87171',
          tag: '#a78bfa',
        },
        canvas: '#1a1f1a',
        sidebar: '#111611',
      },
    },
  },
  plugins: [],
}

