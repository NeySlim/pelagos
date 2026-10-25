// SPDX-License-Identifier: Apache-2.0
// Motion v2 primitives: odometer cells and direction, procedure marks, ruler ticks,
// Poisson spacing, FLIP, the shared loop and its gates, rows, cursors and skeletons.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { useRef } from 'react'
import { MotionProvider } from '../../contexts/MotionContext'
import {
  Checklist,
  NavCursor,
  Readout,
  RollingNumber,
  RowEnter,
  RowLeave,
  Ruler,
  ScaleBar,
  SignalLink,
  Skeleton,
  SkeletonTable,
  StepRail,
  SwapText,
  TabInk,
  AmbientScreen,
  flipRows,
  niceTicks,
  poissonGap,
  progressOf,
  rollCells,
  rollDirection,
  useAnimationLoop,
  loopStats,
} from '.'

const withLevel = (level, ui) => {
  localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: level }))
  return render(<MotionProvider>{ui}</MotionProvider>)
}

beforeEach(() => localStorage.clear())
afterEach(() => vi.restoreAllMocks())

describe('RollingNumber', () => {
  it('aligns characters right and rolls only the ones that change', () => {
    expect(rollCells('42', '43')).toEqual([{ char: '4', from: '4' }, { char: '3', from: '2' }])
    expect(rollCells('99', '100')).toEqual([{ char: '1', from: '' }, { char: '0', from: '9' }, { char: '0', from: '9' }])
    expect(rollDirection('837 /s', '1.24 k/s')).toBe('up')
    expect(rollDirection('12', '3')).toBe('down')
    expect(rollDirection('a', 'b', 'down')).toBe('down')
  })

  it('reads the final value, and rolls changed characters in the sign of the change', () => {
    const { container, rerender } = render(<RollingNumber value={2026102401} />)
    expect(container.querySelector('.sr-only')).toHaveTextContent('2026102401')
    expect(container.querySelectorAll('.fx-roll-out')).toHaveLength(0)
    rerender(<RollingNumber value={2026102402} />)
    expect(container.querySelector('.sr-only')).toHaveTextContent('2026102402')
    expect(container.querySelectorAll('.fx-roll-in')).toHaveLength(1)
    expect(container.querySelector('.fx-roll')).toHaveClass('is-delta')
    expect(container.querySelector('.fx-roll')).not.toHaveClass('is-down')
    rerender(<RollingNumber value={2026102399} />)
    expect(container.querySelector('.fx-roll')).toHaveClass('is-down')
    expect(container.querySelectorAll('.fx-roll-in')).toHaveLength(3)
  })

  it('a unit is part of the text and rolls with it', () => {
    const { container, rerender } = render(<RollingNumber value="837 /s" />)
    rerender(<RollingNumber value="1.24 k/s" />)
    const rolled = [...container.querySelectorAll('.fx-roll-in')].map((n) => n.textContent).join('')
    expect(rolled).toContain('k')
  })

  it('jumps at motion level off', () => {
    const { container, rerender } = withLevel('off', <RollingNumber value={1} />)
    rerender(<MotionProvider><RollingNumber value={2} /></MotionProvider>)
    expect(container.querySelectorAll('.fx-roll-out')).toHaveLength(0)
    expect(container.querySelector('.fx-roll')).not.toHaveClass('is-delta')
    expect(container.querySelector('.sr-only')).toHaveTextContent('2')
  })

  it('SwapText crossfades a label and keeps the new one readable', () => {
    const { container, rerender } = render(<SwapText text="ns2 behind by 1" />)
    rerender(<SwapText text="in sync" />)
    expect(container.querySelector('.fx-swap-in')).toHaveTextContent('in sync')
    expect(container.querySelector('.fx-swap-out')).toHaveAttribute('aria-hidden', 'true')
  })
})

describe('procedures', () => {
  it('a checklist counts done checks, fills its rail and writes each state', () => {
    render(
      <Checklist
        items={[
          { id: 'a', label: 'Preconditions', state: 'done', ms: 12 },
          { id: 'b', label: 'named-checkzone', state: 'running' },
          { id: 'c', label: 'kea config-test', state: 'pending' },
        ]}
      />,
    )
    expect(screen.getByTestId('checklist-count').querySelector('.sr-only')).toHaveTextContent('1/3')
    expect(screen.getByText('Done')).toBeInTheDocument()
    expect(screen.getByText('Running')).toBeInTheDocument()
    expect(screen.getByText('12 ms')).toBeInTheDocument()
    expect(document.querySelector('.fx-checklist-rail > i').style.transform).toBe('scaleY(0.500)')
  })

  it('a step rail fills by step, carries node chips at their duration, and walks back', () => {
    const steps = [
      { id: 'w', label: 'Write', state: 'done', nodes: [{ name: 'ns1', state: 'done', durationMs: 180 }] },
      { id: 'r', label: 'Reload', state: 'running', nodes: [{ name: 'ns1', state: 'running', durationMs: 420 }, { name: 'ns2', state: 'pending' }] },
    ]
    const { rerender } = render(<StepRail steps={steps} />)
    expect(screen.getAllByTestId('step-rail-step')).toHaveLength(2)
    expect(document.querySelector('.fx-rail-fill').style.transform).toBe('scaleY(0.750)')
    const chip = screen.getAllByText('ns1')[1]
    expect(chip).toHaveClass('fx-node-chip', 'is-running')
    expect(chip.style.getPropertyValue('--fx-dn')).toBe('420ms')
    rerender(<StepRail reverse steps={steps.map((s, i) => ({ ...s, state: i === 1 ? 'reverted' : 'done' }))} />)
    expect(screen.getByTestId('step-rail')).toHaveClass('is-reverse')
    expect(document.querySelector('.fx-rail-fill').style.transform).toBe('scaleY(0.500)')
    expect(progressOf([])).toBe(0)
  })
})

describe('instrument marks', () => {
  it('picks round ruler ticks and places them by value', () => {
    expect(niceTicks(600)).toEqual([0, 200, 400, 600])
    expect(niceTicks(7, 3)).toEqual([0, 5])
    expect(niceTicks(0)).toEqual([0])
    render(<Ruler max={800} />)
    const ticks = screen.getByTestId('ruler').querySelectorAll('.fx-ruler-tick')
    expect([...ticks].map((t) => t.textContent)).toEqual(['200', '400', '600', '800'])
    expect(ticks[3].style.transform).toBe('translateY(0.00%)')
  })

  it('readout and scale bar are decorative labels', () => {
    render(
      <div>
        <Readout channel="CH1" unit="q/s" rate="0.25 S/s" count={142} />
        <ScaleBar ratio={1.5} label="10 s" />
      </div>,
    )
    expect(screen.getByTestId('readout')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByTestId('readout').querySelector('.fx-roll')).toHaveAttribute('data-value', '00142')
    expect(screen.getByTestId('scalebar').querySelector('i').style.transform).toBe('scaleX(1.500)')
  })

  it('spaces link ticks as a Poisson process at the rate', () => {
    expect(poissonGap(0)).toBe(Infinity)
    expect(poissonGap(2, () => 1 - Math.exp(-1))).toBeCloseTo(500)
    let total = 0
    let n = 0
    let seed = 1
    const rng = () => ((seed = (seed * 16807) % 2147483647) / 2147483647)
    while (n < 4000) {
      total += poissonGap(4, rng)
      n += 1
    }
    expect(total / n).toBeGreaterThan(230)
    expect(total / n).toBeLessThan(270)
  })

  it('a signal link refuses pulses below full motion and when the partner is down', () => {
    const ref = { current: null }
    const { unmount } = withLevel('reduced', <SignalLink ref={ref} />)
    expect(ref.current.pulse()).toBe(false)
    unmount()
    localStorage.clear()
    const { rerender } = render(<SignalLink ref={ref} state="down" />)
    expect(screen.getByTestId('signal-link')).toHaveAttribute('data-state', 'down')
    expect(ref.current.transfer({ label: 'IXFR 2 RR' })).toBe(false)
    rerender(<SignalLink ref={ref} />)
    expect(ref.current.pulse({ tone: 'dns' })).toBe(true)
  })
})

describe('flipRows', () => {
  function rowsAt(tops) {
    return tops.map((top) => {
      const el = document.createElement('div')
      document.body.appendChild(el)
      el.getBoundingClientRect = () => ({ top: el.__top ?? top })
      el.__top = top
      return el
    })
  }

  it('inverts each moved row, then lets it glide and cleans up', () => {
    const rows = rowsAt([0, 36, 72])
    const moved = flipRows(rows, () => {
      rows[0].__top = 72
      rows[2].__top = 0
    }, 'full')
    expect(moved).toBe(2)
    expect(rows[0]).toHaveClass('fx-flip')
    expect(rows[0].style.transform).toBe('')
    expect(rows[1]).not.toHaveClass('fx-flip')
    rows[0].dispatchEvent(new Event('transitionend'))
    expect(rows[0]).not.toHaveClass('fx-flip')
  })

  it('only mutates below full motion', () => {
    const rows = rowsAt([0, 36])
    const mutate = vi.fn()
    expect(flipRows(rows, mutate, 'reduced')).toBe(0)
    expect(mutate).toHaveBeenCalledOnce()
    expect(rows[0]).not.toHaveClass('fx-flip')
  })
})

describe('useAnimationLoop', () => {
  function Animator({ id, onFrame }) {
    useAnimationLoop(onFrame)
    return <span>{id}</span>
  }

  it('shares one requestAnimationFrame between animators at full motion', () => {
    const raf = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 7)
    vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})
    const { unmount } = render(
      <MotionProvider>
        <Animator id="a" onFrame={() => {}} />
        <Animator id="b" onFrame={() => {}} />
      </MotionProvider>,
    )
    expect(raf).toHaveBeenCalledTimes(1)
    expect(loopStats().active).toBe(2)
    unmount()
    expect(loopStats().active).toBe(0)
  })

  it('never registers below full motion', () => {
    const raf = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 7)
    withLevel('reduced', <Animator id="a" onFrame={() => {}} />)
    expect(raf).not.toHaveBeenCalled()
    expect(loopStats().active).toBe(0)
  })

  it('stops while the page is hidden', () => {
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 7)
    vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible')
    const { unmount } = render(
      <MotionProvider>
        <Animator id="a" onFrame={() => {}} />
      </MotionProvider>,
    )
    expect(loopStats().active).toBe(1)
    visibility.mockReturnValue('hidden')
    act(() => document.dispatchEvent(new Event('visibilitychange')))
    expect(loopStats().active).toBe(0)
    expect(loopStats().running).toBe(false)
    unmount()
  })
})

describe('rows, cursors, skeletons, ambient', () => {
  it('a new row starts folded at full motion and only fades below', () => {
    vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 1)
    const table = (ui) => <table><tbody>{ui}</tbody></table>
    const { container, unmount } = render(table(<RowEnter><td>www</td></RowEnter>))
    const row = container.querySelector('tr')
    expect(row).toHaveClass('fx-row', 'is-folded', 'is-highlight')
    expect(row.querySelector('.fx-cw .fx-cw-pad')).toHaveTextContent('www')
    unmount()
    const reduced = withLevel('reduced', table(<RowEnter><td>www</td></RowEnter>))
    expect(reduced.container.querySelector('tr')).not.toHaveClass('is-folded')
  })

  it('a leaving row reports once it is gone', async () => {
    vi.useFakeTimers()
    const onLeft = vi.fn()
    render(<table><tbody><RowLeave onLeft={onLeft}><td>old</td></RowLeave></tbody></table>)
    expect(onLeft).not.toHaveBeenCalled()
    act(() => vi.advanceTimersByTime(300))
    expect(onLeft).toHaveBeenCalledOnce()
    vi.useRealTimers()
  })

  it('the cursors are decorative and measure their container', () => {
    function Host() {
      const nav = useRef(null)
      const tabs = useRef(null)
      return (
        <div>
          <nav ref={nav}><a aria-current="page">Zones</a><NavCursor container={nav} activeKey="zones" /></nav>
          <div ref={tabs}><button className="is-active">Records</button><TabInk container={tabs} activeKey="records" /></div>
        </div>
      )
    }
    render(<Host />)
    expect(screen.getByTestId('nav-cursor')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByTestId('tab-ink')).toHaveAttribute('aria-hidden', 'true')
  })

  it('a skeleton is a busy status with a calibration sweep', () => {
    render(<div><Skeleton lines={3} /><SkeletonTable columns={4} rows={2} /></div>)
    const sk = screen.getByTestId('skeleton')
    expect(sk).toHaveAttribute('aria-busy', 'true')
    expect(sk.querySelectorAll('.fx-skeleton-line')).toHaveLength(3)
    expect(sk.querySelector('.fx-sweep')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByTestId('skeleton-table').querySelectorAll('.fx-skeleton-line')).toHaveLength(8)
  })

  it('the ambient screen is decorative and gated as a loop', () => {
    render(<AmbientScreen />)
    const amb = screen.getByTestId('ambient-screen')
    expect(amb).toHaveAttribute('aria-hidden', 'true')
    expect(amb.querySelectorAll('.fx-loop')).toHaveLength(2)
  })
})
