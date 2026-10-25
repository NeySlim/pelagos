// SPDX-License-Identifier: Apache-2.0
// Ambient layers: drawing maths, and the gates (ambient preference, motion level, hidden
// page, Instrument family) that decide whether anything exists, moves or holds a frame.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ThemeContext } from '../../contexts/ThemeContext'
import { MotionProvider } from '../../contexts/MotionContext'
import { AmbientDots, AmbientScreen, AmbientSpectrum, AmbientTile, AmbientWave, RegMarks, Ruler, Sweep, loopStats } from '.'
import { RIPPLE_MS, rippleRadius, spectrumLevels, waveAmplitude } from './ambientDraw'

let family = 'instrument'

const wrap = (ui) => (
  <ThemeContext.Provider value={{ effects: family }}>
    <MotionProvider>{ui}</MotionProvider>
  </ThemeContext.Provider>
)

const setup = (prefs, ui) => {
  localStorage.setItem('pelagos-preferences', JSON.stringify(prefs))
  return render(wrap(ui))
}

const layers = (pulse = 1) => (
  <div>
    <AmbientScreen />
    <AmbientTile>
      <AmbientWave rate={5} peak={10} />
      <AmbientSpectrum values={[1, 2, 3]} />
      <AmbientDots pulse={pulse} />
    </AmbientTile>
    <RegMarks pulse={pulse} />
    <Sweep trigger={pulse} />
  </div>
)

beforeEach(() => {
  family = 'instrument'
  localStorage.clear()
  // jsdom has no canvas: a recording stub is enough to prove a frame is painted.
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
})
afterEach(() => vi.restoreAllMocks())

describe('ambient drawing maths', () => {
  it('wave amplitude follows the rate between 3 and 12 percent', () => {
    expect(waveAmplitude(0, 100)).toBeCloseTo(0.03)
    expect(waveAmplitude(100, 100)).toBeCloseTo(0.12)
    expect(waveAmplitude(500, 100)).toBeCloseTo(0.12)
    expect(waveAmplitude(5, 0)).toBeCloseTo(0.03)
  })

  it('the spectrum keeps the last 28 samples, newest right, scaled to the largest', () => {
    const levels = spectrumLevels([2, 4])
    expect(levels).toHaveLength(28)
    expect(levels.slice(0, 26).every((l) => l === 0)).toBe(true)
    expect(levels.slice(26)).toEqual([0.5, 1])
    expect(spectrumLevels(Array.from({ length: 40 }, (_, i) => i + 1))[0]).toBeCloseTo(13 / 40)
    expect(spectrumLevels([0, 0]).every((l) => l === 0)).toBe(true)
  })

  it('a ripple leaves at 260 px/s and is gone after 1.3 s', () => {
    expect(rippleRadius(null)).toBeNull()
    expect(rippleRadius(500)).toBeCloseTo(130)
    expect(rippleRadius(RIPPLE_MS)).toBeNull()
  })
})

describe('ambient gates', () => {
  it('ambient off renders no layer at all', () => {
    setup({ animations: 'full', ambient: 'off' }, layers())
    for (const id of ['ambient-screen', 'ambient-tile', 'ambient-wave', 'ambient-spectrum', 'ambient-dots', 'reg-marks', 'tile-sweep']) {
      expect(screen.queryByTestId(id)).toBeNull()
    }
    expect(loopStats().active).toBe(0)
  })

  it('other families draw no tile layer', () => {
    family = 'mission'
    setup({ animations: 'full', ambient: 'on' }, layers())
    expect(screen.queryByTestId('ambient-tile')).toBeNull()
    expect(screen.queryByTestId('reg-marks')).toBeNull()
    expect(loopStats().active).toBe(0)
  })

  it('full motion draws the layers and joins the one loop, released on unmount', () => {
    const { unmount } = setup({ animations: 'full', ambient: 'on' }, layers())
    for (const id of ['ambient-wave', 'ambient-spectrum', 'ambient-dots', 'reg-marks', 'tile-sweep']) {
      expect(screen.getByTestId(id)).toHaveAttribute('aria-hidden', 'true')
    }
    expect(loopStats().active).toBe(1)
    unmount()
    expect(loopStats().active).toBe(0)
  })

  it.each(['reduced', 'off'])('%s motion holds a static frame: layers exist, no loop, no ping, no sweep', (animations) => {
    const { rerender } = setup({ animations, ambient: 'on' }, layers(1))
    expect(screen.getByTestId('ambient-wave')).toBeInTheDocument()
    rerender(wrap(layers(2)))
    expect(loopStats().active).toBe(0)
    expect(screen.getByTestId('reg-marks')).not.toHaveClass('is-ping')
    expect(document.querySelector('.fx-sweep.is-go')).toBeNull()
  })

  it('full motion pings the marks and sweeps once per event, not on mount', () => {
    const { rerender } = setup({ animations: 'full', ambient: 'on' }, layers(1))
    expect(screen.getByTestId('reg-marks')).not.toHaveClass('is-ping')
    expect(document.querySelector('.fx-sweep.is-go')).toBeNull()
    rerender(wrap(layers(2)))
    expect(screen.getByTestId('reg-marks')).toHaveClass('is-ping')
    expect(document.querySelector('.fx-sweep.is-go')).not.toBeNull()
  })

  it('a hidden page keeps the layers but leaves the loop', () => {
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden')
    setup({ animations: 'full', ambient: 'on' }, layers())
    expect(screen.getByTestId('ambient-wave')).toBeInTheDocument()
    expect(loopStats().active).toBe(0)
  })
})

describe('ruler cursor', () => {
  it('follows the latest sample on the ruler scale', () => {
    render(<Ruler max={100} cursor={25} />)
    expect(screen.getByTestId('ruler-cursor').style.transform).toBe('translateY(75.00%)')
  })

  it('is absent without a cursor value', () => {
    render(<Ruler max={100} />)
    expect(screen.queryByTestId('ruler-cursor')).toBeNull()
  })
})
