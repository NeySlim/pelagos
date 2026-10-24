// SPDX-License-Identifier: Apache-2.0
// A saved theme survives a reload, StrictMode's double mount included.
import { StrictMode } from 'react'
import { describe, it, expect, beforeEach } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { ThemeProvider } from './ThemeContext'

describe('ThemeProvider', () => {
  beforeEach(() => localStorage.clear())

  it('starts from the saved mode and family', async () => {
    localStorage.setItem('pelagos-theme-mode', 'dark')
    localStorage.setItem('pelagos-theme-family', 'gray')
    render(
      <StrictMode>
        <ThemeProvider>
          <span>x</span>
        </ThemeProvider>
      </StrictMode>,
    )
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('dark'))
    expect(localStorage.getItem('pelagos-theme-mode')).toBe('dark')
    expect(localStorage.getItem('pelagos-theme-family')).toBe('gray')
  })

  it('ignores invalid saved values', async () => {
    localStorage.setItem('pelagos-theme-mode', 'neon')
    render(
      <ThemeProvider>
        <span>x</span>
      </ThemeProvider>,
    )
    // matchMedia is stubbed to "not dark": system mode resolves to light.
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('light'))
    expect(localStorage.getItem('pelagos-theme-mode')).toBe('system')
  })
})
