// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify('test'),
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.test.{js,jsx}', 'mock/**/*.test.{js,mjs}'],
    exclude: ['node_modules/', 'e2e/**'],
    // The icon barrel is thousands of modules; pre-bundled it loads in a fraction of a second.
    deps: {
      optimizer: {
        client: { enabled: true, include: ['@phosphor-icons/react'] },
      },
    },
    pool: 'forks',
    maxForks: 2,
    minForks: 1,
  },
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
})
