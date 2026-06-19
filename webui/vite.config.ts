import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: 'hidden',
    minify: false,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:3000',
      '/static': 'http://localhost:3000'
    }
  }
})
