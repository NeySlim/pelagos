// SPDX-License-Identifier: Apache-2.0
// The cluster trace engine on a recording canvas: drawing below full motion happens on
// data and pointer changes only, the playhead reads the nearest sample, snaps to an event
// within 7 px, scrubTo holds it at an instant and release lets it go. Also the strip
// chart, the DORA ticks, the heartbeat ECG and the canvas inks.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { createRef } from 'react'
import { MotionProvider } from '../../contexts/MotionContext'
import { ClusterTrace, Dora, HeartbeatTrace, StripChart, ThresholdTrace, stripGeometry } from '.'
import { parseColor, ink } from './canvasInk'

const W = 916
const H = 300
let observers = []
let calls = []

function fakeContext() {
  const target = { canvas: null }
  return new Proxy(target, {
    get(t, key) {
      if (key in t) return t[key]
      return (...args) => {
        calls.push([key, ...args])
        return key === 'createLinearGradient' ? { addColorStop() {} } : undefined
      }
    },
    set(t, key, value) {
      t[key] = value
      return true
    },
  })
}

const withLevel = (level, ui) => {
  localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: level }))
  return render(<MotionProvider>{ui}</MotionProvider>)
}

// Delivers a size to every observed canvas, as the browser's ResizeObserver would.
function layout() {
  act(() => {
    for (const o of observers) o.callback([{ contentRect: { width: W, height: H } }])
  })
}

beforeEach(() => {
  localStorage.clear()
  calls = []
  observers = []
  globalThis.ResizeObserver = class {
    constructor(callback) {
      this.callback = callback
      observers.push(this)
    }
    observe() {}
    disconnect() {}
  }
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(() => fakeContext())
  // The paper follows the clock: hold it so positions are exact.
  vi.spyOn(Date, 'now').mockReturnValue(NOW)
})
afterEach(() => vi.restoreAllMocks())

const NOW = Date.now()
const samples = Array.from({ length: 20 }, (_, i) => ({ t: NOW - (19 - i) * 4000, v: 100 + i * 10 }))
const lanes = (events = []) => [
  { type: 'line', key: 'dns', color: 'dns', label: 'DNS queries', readoutLabel: 'queries/s', data: samples, format: (v) => `${v} q/s` },
  { type: 'ecg', key: 'hb', label: 'HA heartbeat', rows: [{ label: 'v4', beats: [1, 2, 3, 4, 5, 6].map((k) => ({ t: NOW - k * 10000 })) }] },
  { type: 'events', key: 'events', label: 'Events', data: events },
]

describe('cluster trace', () => {
  it('stays off the loop below full motion and draws when its data changes', () => {
    const { rerender } = withLevel('reduced', <ClusterTrace lanes={lanes()} />)
    layout()
    const trace = screen.getByTestId('cluster-trace')
    expect(trace).toHaveAttribute('data-running', 'false')
    const drawn = calls.filter((c) => c[0] === 'stroke').length
    expect(drawn).toBeGreaterThan(0)
    expect(calls.some((c) => c[0] === 'fillText' && c[1] === 'DNS queries')).toBe(true)
    expect(calls.some((c) => c[0] === 'fillText' && c[1] === '-10 s')).toBe(true)
    calls = []
    rerender(
      <MotionProvider>
        <ClusterTrace lanes={lanes([{ t: NOW - 5000, kind: 'plan' }])} />
      </MotionProvider>,
    )
    expect(calls.some((c) => c[0] === 'rect' && c[3] === 7)).toBe(true)
  })

  it('runs on the shared loop at full motion', () => {
    withLevel('full', <ClusterTrace lanes={lanes()} />)
    expect(screen.getByTestId('cluster-trace')).toHaveAttribute('data-running', 'true')
  })

  it('reads the nearest sample under the pointer and snaps to an event within 7 px', () => {
    const plan = { t: NOW - 45000, kind: 'plan' }
    withLevel('reduced', <ClusterTrace lanes={lanes([plan])} eventLabel={(e) => `plan at ${e.t}`} labels={{ hbInterval: 'hb interval' }} />)
    layout()
    const trace = screen.getByTestId('cluster-trace')
    vi.spyOn(trace, 'getBoundingClientRect').mockReturnValue({ left: 0, top: 0, width: W, height: H })
    const readout = screen.getByTestId('cluster-trace-readout')
    // x of 45 s ago on a 900 px plot of 90 s: 458; 5 px off still lands on the plan.
    fireEvent.pointerMove(trace, { clientX: 463, clientY: 100 })
    expect(readout).toHaveClass('is-on')
    expect(readout).toHaveTextContent(`plan at ${plan.t}`)
    expect(readout).toHaveTextContent('queries/s')
    expect(readout).toHaveTextContent('-45.0 s')
    expect(readout).toHaveTextContent('hb interval10.00 s')
    // 9 px off: no snap, the exact instant under the pointer.
    fireEvent.pointerMove(trace, { clientX: 467, clientY: 100 })
    expect(readout).not.toHaveTextContent('plan at')
    fireEvent.pointerLeave(trace)
    expect(readout).not.toHaveClass('is-on')
  })

  it('holds the playhead at an instant with scrubTo until release', () => {
    const ref = createRef()
    withLevel('reduced', <ClusterTrace ref={ref} lanes={lanes()} />)
    layout()
    const readout = screen.getByTestId('cluster-trace-readout')
    act(() => ref.current.scrubTo(NOW - 29000))
    expect(readout).toHaveClass('is-on')
    expect(readout).toHaveTextContent('-29.0 s')
    // The nearest sample to 29 s ago is the one 28 s ago.
    expect(readout).toHaveTextContent(`${samples[12].v} q/s`)
    act(() => ref.current.release())
    expect(readout).not.toHaveClass('is-on')
  })

  it('applies a new window at once below full motion', () => {
    const { rerender } = withLevel('reduced', <ClusterTrace lanes={lanes()} windowMs={90000} />)
    layout()
    calls = []
    rerender(
      <MotionProvider>
        <ClusterTrace lanes={lanes()} windowMs={30000} />
      </MotionProvider>,
    )
    expect(screen.getByTestId('cluster-trace')).toHaveAttribute('data-window', '30000')
    // At 30 s the 5 s ticks are labelled.
    expect(calls.some((c) => c[0] === 'fillText' && c[1] === '-5 s')).toBe(true)
  })

  it('draws threshold lines and latches on a threshold trace', () => {
    const pressure = samples.map((s, i) => ({ t: s.t, v: 80 + i }))
    withLevel('reduced', (
      <ThresholdTrace
        samples={pressure}
        thresholds={[{ v: 80, label: '80' }, { v: 95, label: '95', bad: true }]}
        latches={[{ t: pressure[15].t, v: 95, state: 'open' }]}
        windowMs={90000}
        min={60}
        max={104}
        channel="CH2"
        unit="% used"
      />
    ))
    layout()
    expect(calls.some((c) => c[0] === 'fillText' && c[1] === '95')).toBe(true)
    expect(calls.filter((c) => c[0] === 'arc' && c[3] === 3.5)).toHaveLength(1)
    expect(screen.getByTestId('threshold-trace')).toHaveTextContent('CH2')
  })
})

describe('strip chart', () => {
  it('right-aligns the samples over their slots with 15 % headroom', () => {
    const g = stripGeometry([{ t: 1, v: 10 }, { t: 2, v: 20 }], { width: 300, height: 92, slots: 45, kind: 'line' })
    expect(g.offset).toBe(43)
    expect(g.x(1)).toBeCloseTo(300 - 8 - 22)
    expect(g.max).toBeCloseTo(23)
    expect(g.y(g.max)).toBe(16)
    expect(g.y(0)).toBe(92 - 14)
  })

  it('slides the paper one slot over the sample interval at full motion only', () => {
    const pts = [{ t: 0, v: 1 }, { t: 4000, v: 2 }]
    const { container, rerender } = withLevel('full', <StripChart points={pts} />)
    const paper = container.querySelector('.fx-strip-paper')
    rerender(
      <MotionProvider>
        <StripChart points={[...pts, { t: 8000, v: 3 }]} />
      </MotionProvider>,
    )
    expect(paper.style.transition).toBe('transform 4000ms linear')
    expect(paper.style.transform).toBe('translateX(0)')
    localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: 'reduced' }))
  })

  it('reads the sample under the pointer', () => {
    const pts = Array.from({ length: 45 }, (_, i) => ({ t: i * 4000, v: i }))
    withLevel('reduced', <StripChart points={pts} format={(v) => `${v} q/s`} formatTime={(t) => `t${t}`} />)
    const strip = screen.getByTestId('strip-chart')
    vi.spyOn(strip, 'getBoundingClientRect').mockReturnValue({ left: 0, top: 0, width: 300, height: 92 })
    fireEvent.pointerMove(strip, { clientX: 8, clientY: 40 })
    expect(screen.getByTestId('strip-chart-readout')).toHaveTextContent('t0 0 q/s')
  })
})

describe('lease and heartbeat marks', () => {
  it('lands the DORA ticks on each new exchange, red on a NAK, still when off', () => {
    const { rerender } = withLevel('full', <Dora beat={1} />)
    const dora = () => screen.getByTestId('dora')
    expect(dora()).toHaveClass('is-on')
    expect(dora()).not.toHaveClass('is-go')
    rerender(<MotionProvider><Dora beat={2} nak /></MotionProvider>)
    expect(dora()).toHaveClass('is-go')
    expect(dora()).toHaveClass('is-nak')
    expect(dora()).toHaveAttribute('data-gen', '1')
  })

  it('does not land the ticks when motion is off', () => {
    const { rerender } = withLevel('off', <Dora beat={1} />)
    rerender(<MotionProvider><Dora beat={2} /></MotionProvider>)
    expect(screen.getByTestId('dora')).not.toHaveClass('is-go')
  })

  it('draws the ECG on a heartbeat and dashes it when the partner is lost', () => {
    const { container, rerender } = withLevel('full', <HeartbeatTrace beat={1} />)
    expect(container.querySelector('path')).not.toHaveClass('is-beat')
    rerender(<MotionProvider><HeartbeatTrace beat={2} /></MotionProvider>)
    expect(container.querySelector('path')).toHaveClass('is-beat')
    rerender(<MotionProvider><HeartbeatTrace beat={2} lost /></MotionProvider>)
    expect(screen.getByTestId('heartbeat-trace')).toHaveClass('is-lost')
  })
})

describe('canvas inks', () => {
  it('parses computed colors in every form the browser returns', () => {
    expect(parseColor('rgb(95, 199, 230)')).toEqual([95, 199, 230, 1])
    expect(parseColor('rgba(255, 255, 255, 0.07)')).toEqual([255, 255, 255, 0.07])
    expect(parseColor('color(srgb 1 0.5 0 / 0.24)')).toEqual([255, 127.5, 0, 0.24])
    expect(parseColor('#5FC7E6')).toEqual([95, 199, 230, 1])
    expect(parseColor('#fff')).toEqual([255, 255, 255, 1])
    expect(parseColor('nonsense')).toBeNull()
    expect(ink([255, 255, 255, 0.5], 0.5)).toBe('rgba(255,255,255,0.25)')
  })
})
