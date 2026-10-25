// SPDX-License-Identifier: Apache-2.0
// Domain marks and traces: DORA ticks, heartbeat traces, the unsent queue, transfers that
// roll a serial on arrival, the serial trace playhead and the threshold latches, at every
// motion level; and the geometry behind the traces.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { createRef } from 'react'
import { MotionProvider } from '../../contexts/MotionContext'
import { Dora, HeartbeatTrace, SerialTrace, ThresholdTrace, TransferSerial, UnsentQueue } from '.'
import { clipPoints, crossingTime, levelOf, rulerStep, rulerTicks, snapMarker, stepLevels, timeToX, valueAt, xToTime } from './traceMath'

const withLevel = (level, ui) => {
  localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: level }))
  return render(<MotionProvider>{ui}</MotionProvider>)
}
// Rerenders under the provider of withLevel: the level stays the one it was given.
const again = (ui) => <MotionProvider>{ui}</MotionProvider>

beforeEach(() => localStorage.clear())
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('trace geometry', () => {
  it('maps time to x on a window ending now, and back', () => {
    expect(timeToX(1000, 1000, 300, 0, 600)).toBe(600)
    expect(timeToX(700, 1000, 300, 0, 600)).toBe(0)
    expect(xToTime(300, 1000, 300, 0, 600)).toBe(850)
  })

  it('reads step series, ranks serials and finds crossings', () => {
    const points = [[0, 10], [100, 11], [200, 12]]
    expect(valueAt(points, -1)).toBeUndefined()
    expect(valueAt(points, 150)).toBe(11)
    const levels = stepLevels([{ points }, { points: [[0, 10], [180, 11]] }], 50)
    expect(levels).toEqual([10, 11, 12])
    expect(levelOf(levels, 12)).toBe(1)
    expect(levelOf([5], 5)).toBe(0.5)
    expect(crossingTime([[0, 70], [10, 90], [20, 100]], 80)).toBe(5)
    expect(crossingTime([[0, 70], [10, 75]], 80)).toBeNull()
    expect(clipPoints(points, 120, 300)).toEqual([[100, 11], [200, 12]])
  })

  it('chooses round ruler steps and snaps the playhead to a near marker', () => {
    expect(rulerStep(300000)).toBe(60000)
    expect(rulerStep(30000)).toBe(5000)
    expect(rulerTicks(1000000, 300000).map((t) => t.ago)).toEqual([0, 60000, 120000, 180000, 240000, 300000])
    const markers = [{ t: 100 }, { t: 200 }]
    expect(snapMarker(markers, 104, (t) => t)).toEqual({ t: 100 })
    expect(snapMarker(markers, 150, (t) => t)).toBeNull()
  })
})

describe('Dora', () => {
  it('lands its ticks at full and reduced, stands still at off, stops on red for a NAK', () => {
    const { container, unmount } = withLevel('full', <Dora />)
    expect(container.querySelector('.fx-dora')).toHaveClass('is-go')
    expect(container.querySelectorAll('.fx-dora > i')).toHaveLength(4)
    unmount()
    withLevel('off', <Dora nak />)
    expect(screen.getByTestId('dora')).not.toHaveClass('is-go')
    expect(screen.getByTestId('dora')).toHaveClass('is-nak')
    expect(screen.getByTestId('dora')).toHaveAttribute('data-state', 'nak')
  })

  it('fades away after landing when it marks a table row', () => {
    vi.useFakeTimers()
    const done = vi.fn()
    withLevel('full', <Dora transient onDone={done} />)
    act(() => vi.advanceTimersByTime(1900))
    expect(screen.getByTestId('dora')).toHaveClass('is-gone')
    act(() => vi.advanceTimersByTime(300))
    expect(screen.queryByTestId('dora')).toBeNull()
    expect(done).toHaveBeenCalledTimes(1)
  })
})

describe('HeartbeatTrace', () => {
  it('traces one QRS per beat received, and a red flat line when the partner is lost', () => {
    const { container, rerender } = withLevel('full', <HeartbeatTrace beat={0} />)
    expect(container.querySelector('.fx-ecg-qrs')).not.toHaveClass('is-beat')
    rerender(again(<HeartbeatTrace beat={1} />))
    expect(screen.getByTestId('heartbeat')).toHaveAttribute('data-beats', '1')
    expect(container.querySelector('.fx-ecg-qrs')).toHaveClass('is-beat')
    rerender(again(<HeartbeatTrace beat={1} lost />))
    expect(screen.getByTestId('heartbeat')).toHaveClass('is-lost')
    expect(container.querySelector('.fx-ecg-flat')).toBeInTheDocument()
  })

  it('does not trace at off', () => {
    const { container, rerender } = withLevel('off', <HeartbeatTrace beat={0} />)
    rerender(again(<HeartbeatTrace beat={2} />))
    expect(screen.getByTestId('heartbeat')).toHaveAttribute('data-beats', '1')
    expect(container.querySelector('.fx-ecg-qrs')).not.toHaveClass('is-beat')
  })
})

describe('UnsentQueue', () => {
  it('fills with one tick per update and drains them toward the partner', () => {
    vi.useFakeTimers()
    const { container, rerender } = withLevel('full', <UnsentQueue count={0} />)
    expect(container.querySelectorAll('.fx-queue-slots > i')).toHaveLength(0)
    rerender(again(<UnsentQueue count={3} />))
    expect(container.querySelectorAll('.fx-queue-slots > i.is-in')).toHaveLength(3)
    expect(screen.getByTestId('unsent-queue')).toHaveAttribute('data-count', '3')
    rerender(again(<UnsentQueue count={0} />))
    expect(container.querySelectorAll('.fx-queue-slots > i.is-out')).toHaveLength(3)
    expect(screen.getByTestId('unsent-queue')).toHaveAttribute('data-draining', 'true')
    act(() => vi.advanceTimersByTime(1000))
    expect(container.querySelectorAll('.fx-queue-slots > i')).toHaveLength(0)
    rerender(again(<UnsentQueue count={40} />))
    expect(container.querySelectorAll('.fx-queue-slots > i')).toHaveLength(24)
    expect(container.querySelector('.fx-queue-slots > b')).toHaveTextContent('+')
  })

  it('changes at once at off', () => {
    const { container, rerender } = withLevel('off', <UnsentQueue count={2} />)
    rerender(again(<UnsentQueue count={0} />))
    expect(container.querySelectorAll('.fx-queue-slots > i')).toHaveLength(0)
    rerender(again(<UnsentQueue count={null} />))
    expect(screen.getByTestId('unsent-queue')).toHaveTextContent('-')
  })
})

describe('TransferSerial', () => {
  it('at full the transfer runs first, the serial rolls on arrival and its cell lights once', () => {
    vi.useFakeTimers()
    const { container, rerender } = withLevel('full', <TransferSerial value={2026102401} testId="xs" />)
    rerender(again(<TransferSerial value={2026102402} testId="xs" />))
    expect(screen.getByTestId('transfer-bar')).toHaveAttribute('data-run', '1')
    expect(screen.getByTestId('xs')).toHaveAttribute('data-value', '2026102401')
    act(() => vi.advanceTimersByTime(600))
    expect(screen.getByTestId('xs')).toHaveAttribute('data-value', '2026102402')
    expect(container.querySelector('.fx-hl-a')).toBeInTheDocument()
  })

  it('has no travel in reduced and no highlight at off; a serial that was not behind just rolls', () => {
    const reduced = withLevel('reduced', <TransferSerial value={10} testId="xs" />)
    reduced.rerender(again(<TransferSerial value={11} testId="xs" />))
    expect(screen.getByTestId('xs')).toHaveAttribute('data-value', '11')
    expect(screen.getByTestId('transfer-bar')).not.toHaveAttribute('data-run')
    expect(reduced.container.querySelector('.fx-hl-a')).toBeInTheDocument()
    reduced.unmount()
    const off = withLevel('off', <TransferSerial value={11} testId="xs" />)
    off.rerender(again(<TransferSerial value={12} testId="xs" />))
    expect(screen.getByTestId('xs')).toHaveAttribute('data-value', '12')
    expect(off.container.querySelector('.fx-hl-a, .fx-hl-b')).toBeNull()
    off.unmount()
    const full = withLevel('full', <TransferSerial value={12} transfer={false} testId="xs" />)
    full.rerender(again(<TransferSerial value={13} transfer={false} testId="xs" />))
    expect(screen.getByTestId('transfer-bar')).not.toHaveAttribute('data-run')
    expect(screen.getByTestId('xs')).toHaveAttribute('data-value', '13')
  })
})

describe('SerialTrace', () => {
  it('moves its playhead to an instant and back without travel below full', async () => {
    const ref = createRef()
    const lanes = [{ id: 'n1', label: 'ns1', points: [[Date.now() - 60000, 1], [Date.now() - 1000, 2]] }]
    withLevel('reduced', <SerialTrace ref={ref} lanes={lanes} markers={[{ t: Date.now() - 1000, kind: 'plan' }]} />)
    expect(screen.getByTestId('serial-trace-readout')).not.toBeVisible()
    await act(() => ref.current.scrubTo(Date.now() - 1500))
    expect(ref.current.scrubbed).not.toBeNull()
    await act(() => ref.current.release())
    expect(ref.current.scrubbed).toBeNull()
  })
})

describe('ThresholdTrace', () => {
  it('lists its latches for the latched, held and released states', () => {
    withLevel('off', <ThresholdTrace points={[[0, 70], [10, 100]]} from={0} to={20} latches={[{ t: 5, value: 95, state: 'held' }, { t: 15, value: 80, state: 'released' }]} thresholds={[{ value: 80 }, { value: 95 }]} />)
    expect(screen.getByTestId('threshold-trace')).toHaveAttribute('data-latches', 'held released')
  })
})
