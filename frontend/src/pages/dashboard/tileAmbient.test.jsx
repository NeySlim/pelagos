// SPDX-License-Identifier: Apache-2.0
// Tile ambient events: marks ping on domain events only, sweeps stagger and follow data.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ThemeContext } from '../../contexts/ThemeContext'
import { MotionProvider } from '../../contexts/MotionContext'
import { DnsTile } from './heroTiles'
import { TileRefresh, changedTiles } from './tileRefresh'
import { summarizeLive } from '../../lib/liveRates'

const TARGETS = [{ key: 'dns:N1', kind: 'dns', node: 'N1' }]
const pts = (n) => Array.from({ length: n }, (_, i) => ({ t: 1000 * (i + 1), v: 100 + i }))
const liveOf = (n) => summarizeLive(TARGETS, { 'dns:N1': { points: pts(n), parts: {} } })
const SUMMARY = { nodes: [], zones: [], ha: [] }

const tree = (n, refresh) => (
  <MemoryRouter>
    <ThemeContext.Provider value={{ effects: 'instrument' }}>
      <MotionProvider>
        <TileRefresh.Provider value={refresh}>
          <DnsTile summary={SUMMARY} editing={false} live={liveOf(n)} />
        </TileRefresh.Provider>
      </MotionProvider>
    </ThemeContext.Provider>
  </MemoryRouter>
)

beforeEach(() => {
  localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: 'full', ambient: 'on' }))
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
})
afterEach(() => vi.restoreAllMocks())

describe('tile ambient events', () => {
  it('a new live sample alone neither pings the marks nor sweeps', () => {
    const { rerender } = render(tree(4, { sweeps: {}, pulses: {}, order: {} }))
    rerender(tree(5, { sweeps: {}, pulses: {}, order: {} }))
    rerender(tree(6, { sweeps: {}, pulses: {}, order: {} }))
    expect(screen.getByTestId('reg-marks')).not.toHaveClass('is-ping')
    expect(document.querySelector('.fx-sweep.is-go')).toBeNull()
  })

  it('a domain event pings the marks, a sweep request staggers by reading order', () => {
    const { rerender } = render(tree(4, { sweeps: { dns: 0 }, pulses: { dns: 0 }, order: { dns: 3 } }))
    rerender(tree(4, { sweeps: { dns: 1 }, pulses: { dns: 1 }, order: { dns: 3 } }))
    expect(screen.getByTestId('reg-marks')).toHaveClass('is-ping')
    expect(document.querySelector('.fx-sweep.is-go').style.animationDelay).toBe('180ms')
  })

  it('draws the wave inside the opaque query panel, under its content', () => {
    render(tree(4, null))
    const panel = screen.getByTestId('ambient-wave').closest('.dash-subpanel')
    expect(panel).not.toBeNull()
    expect(panel.firstElementChild).toHaveClass('is-under')
  })

  it('keeps the ruler gutter and the scale bar to a round duration', () => {
    render(tree(8, null))
    expect(screen.getByTestId('scalebar')).toHaveTextContent('10 s')
    expect(screen.getByTestId('readout')).toHaveTextContent('CH1')
    expect(screen.getByTestId('readout')).toHaveTextContent('q/s')
  })
})

describe('changedTiles', () => {
  it('lists only tiles whose slice changed', () => {
    const a = { nodes: [1], zones: [1], ha: [], pools: [], alerts: {}, d2: [] }
    expect(changedTiles(a, { ...a })).toEqual([])
    expect(changedTiles(a, { ...a, pools: [1] }).sort()).toEqual(['dhcp', 'pools'])
    expect(changedTiles(a, { ...a, zones: [2] }).sort()).toEqual(['dns', 'inconsistencies', 'radar', 'zones'])
  })
})
