// SPDX-License-Identifier: Apache-2.0
// Animation preference: stored with the other preferences, server values win, and the
// system reduced-motion setting and a hidden page lower what actually runs.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen, fireEvent } from '@testing-library/react'
import { MotionProvider, useMotion } from './MotionContext'
import { applyServerPreferences } from '../stores/preferencesStore'

function Probe() {
  const { animations, level, loops, hidden, setAnimations } = useMotion()
  return (
    <div>
      <span data-testid="state">{`${animations}/${level}/${loops ? 'loops' : 'still'}/${hidden ? 'hidden' : 'visible'}`}</span>
      <button type="button" onClick={() => setAnimations('off')}>off</button>
    </div>
  )
}

function stubReducedMotion(matches) {
  window.matchMedia = vi.fn().mockImplementation((query) => ({
    matches: query.includes('reduced-motion') ? matches : false,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
  }))
}

describe('MotionProvider', () => {
  const originalMatchMedia = window.matchMedia
  beforeEach(() => {
    localStorage.clear()
    stubReducedMotion(false)
  })
  afterEach(() => {
    window.matchMedia = originalMatchMedia
    delete document.documentElement.dataset.motion
    delete document.documentElement.dataset.ambient
  })

  it('keeps ambient backgrounds on by default, writes data-ambient and persists a change', () => {
    function Ambient() {
      const { ambient, ambientRunning, setAmbient } = useMotion()
      return <button type="button" onClick={() => setAmbient('off')}>{`${ambient}/${ambientRunning ? 'moving' : 'still'}`}</button>
    }
    render(<MotionProvider><Ambient /></MotionProvider>)
    expect(screen.getByRole('button')).toHaveTextContent('on/moving')
    expect(document.documentElement.dataset.ambient).toBe('on')
    fireEvent.click(screen.getByRole('button'))
    expect(screen.getByRole('button')).toHaveTextContent('off/still')
    expect(document.documentElement.dataset.ambient).toBe('off')
    expect(JSON.parse(localStorage.getItem('pelagos-preferences')).ambient).toBe('off')
    act(() => applyServerPreferences({ ambient: 'on' }))
    expect(screen.getByRole('button')).toHaveTextContent('on/moving')
  })

  it('holds ambient still when the system asks for reduced motion', () => {
    stubReducedMotion(true)
    function Ambient() {
      const { ambientRunning } = useMotion()
      return <span data-testid="amb">{ambientRunning ? 'moving' : 'still'}</span>
    }
    render(<MotionProvider><Ambient /></MotionProvider>)
    expect(screen.getByTestId('amb')).toHaveTextContent('still')
  })

  it('defaults to full motion and writes data-motion', () => {
    render(<MotionProvider><Probe /></MotionProvider>)
    expect(screen.getByTestId('state')).toHaveTextContent('full/full/loops/visible')
    expect(document.documentElement.dataset.motion).toBe('full')
  })

  it('persists a new level in the preferences store', () => {
    render(<MotionProvider><Probe /></MotionProvider>)
    fireEvent.click(screen.getByText('off'))
    expect(screen.getByTestId('state')).toHaveTextContent('off/off/still')
    expect(JSON.parse(localStorage.getItem('pelagos-preferences')).animations).toBe('off')
    expect(document.documentElement.dataset.motion).toBe('off')
  })

  it('starts from the saved preference and follows the server', () => {
    localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: 'reduced' }))
    render(<MotionProvider><Probe /></MotionProvider>)
    expect(screen.getByTestId('state')).toHaveTextContent('reduced/reduced/still')
    act(() => applyServerPreferences({ animations: 'full' }))
    expect(screen.getByTestId('state')).toHaveTextContent('full/full/loops')
    act(() => applyServerPreferences({ animations: 'bogus' }))
    expect(screen.getByTestId('state')).toHaveTextContent('full/full/loops')
  })

  it('lets prefers-reduced-motion lower a full preference', () => {
    stubReducedMotion(true)
    render(<MotionProvider><Probe /></MotionProvider>)
    expect(screen.getByTestId('state')).toHaveTextContent('full/reduced/still')
    expect(document.documentElement.dataset.motion).toBe('reduced')
  })

  it('stops loops while the page is hidden', () => {
    render(<MotionProvider><Probe /></MotionProvider>)
    const spy = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    act(() => document.dispatchEvent(new Event('visibilitychange')))
    expect(screen.getByTestId('state')).toHaveTextContent('full/full/still/hidden')
    expect('pageHidden' in document.documentElement.dataset).toBe(true)
    spy.mockReturnValue('visible')
    act(() => document.dispatchEvent(new Event('visibilitychange')))
    expect(screen.getByTestId('state')).toHaveTextContent('full/full/loops/visible')
    expect('pageHidden' in document.documentElement.dataset).toBe(false)
    spy.mockRestore()
  })
})
