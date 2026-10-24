// SPDX-License-Identifier: Apache-2.0
// Dev server proxies /api to the backend (pelagos serve on 8480) or to the mock
// server (npm run mock, port 8481) when VITE_API_MOCK=1.
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

const useMock = process.env.VITE_API_MOCK === '1'
const mockPort = process.env.MOCK_PORT || '8481'
const apiTarget = process.env.VITE_API_TARGET || (useMock ? `http://127.0.0.1:${mockPort}` : 'http://127.0.0.1:8480')

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version || '0.0.0'),
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    port: Number(process.env.VITE_PORT || 5173),
    strictPort: false,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
        secure: false,
        ws: true,
        // The backend accepts a WebSocket only when Origin matches its own Host, which
        // changeOrigin sets to the target: present the target origin on upgrades too.
        configure: (proxy) => {
          proxy.on('proxyReqWs', (proxyReq) => proxyReq.setHeader('origin', new URL(apiTarget).origin))
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          radix: [
            '@radix-ui/react-dialog',
            '@radix-ui/react-dropdown-menu',
            '@radix-ui/react-tabs',
            '@radix-ui/react-tooltip',
            '@radix-ui/react-select',
          ],
          charts: ['recharts'],
        },
      },
    },
  },
})
