// SPDX-License-Identifier: Apache-2.0
// Motion primitives: counters land on the value (immediately below full level), charts
// render their data, and decorative pieces stay out of the accessibility tree.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MotionProvider } from '../../contexts/MotionContext'
import { CountUp, MiniHistogram, SegmentedProgress, StatusDot, StippledAreaChart, Stagger, RadarRing, StatChip, IconButton, AppBackdrop } from '.'

describe('CountUp', () => {
  beforeEach(() => localStorage.clear())
  afterEach(() => vi.restoreAllMocks())

  it('reads the final value and reserves its width', () => {
    const { container } = render(<CountUp value={1234} />)
    expect(container.querySelector('.sr-only')).toHaveTextContent('1,234')
    expect(container.querySelector('.fx-count-ghost')).toHaveTextContent('1,234')
  })

  it('counts up to the value at full level', async () => {
    const { container } = render(<CountUp value={50} duration={30} />)
    await waitFor(() => expect(container.querySelector('.fx-count-live')).toHaveTextContent('50'))
  })

  it('shows the value at once when animations are reduced', () => {
    localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: 'reduced' }))
    const raf = vi.spyOn(window, 'requestAnimationFrame')
    const { container } = render(
      <MotionProvider>
        <CountUp value={42} suffix=" %" />
      </MotionProvider>,
    )
    expect(container.querySelector('.fx-count-live')).toHaveTextContent('42 %')
    expect(raf).not.toHaveBeenCalled()
  })
})

describe('charts', () => {
  it('scales histogram bars to the largest value', () => {
    render(<MiniHistogram data={[1, 2, 4]} label="queries" />)
    const bars = screen.getByRole('img', { name: 'queries' }).querySelectorAll('rect')
    expect(bars).toHaveLength(3)
    expect(bars[2].style.transform).toBe('scaleY(1)')
    expect(bars[0].style.transform).toBe('scaleY(0.25)')
  })

  it('draws a stippled area with a marker on the current point', () => {
    const { container } = render(<StippledAreaChart points={[1, 3, 2, 5]} label="rate" />)
    expect(screen.getByRole('img', { name: 'rate' })).toBeInTheDocument()
    expect(container.querySelectorAll('path')).toHaveLength(2)
    expect(container.querySelector('.fx-halo')).toBeInTheDocument()
  })

  it('needs two points to draw', () => {
    const { container } = render(<StippledAreaChart points={[1]} />)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('reports segmented progress as done segments', () => {
    render(<SegmentedProgress label="route" segments={[{ state: 'done' }, { state: 'current' }, { state: 'next' }]} />)
    const bar = screen.getByRole('progressbar', { name: 'route' })
    expect(bar).toHaveAttribute('aria-valuenow', '1')
    expect(bar.querySelectorAll('.fx-segment-current')).toHaveLength(1)
  })
})

describe('decor and layout', () => {
  it('hides decorative pieces unless labelled', () => {
    const { container } = render(
      <div>
        <StatusDot tone="success" pulse />
        <StatusDot tone="danger" label="offline" />
        <RadarRing />
        <AppBackdrop />
      </div>,
    )
    expect(screen.getAllByTestId('status-dot')[0]).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByRole('img', { name: 'offline' })).toHaveClass('fx-tone-danger')
    expect(container.querySelectorAll('.fx-loop').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByTestId('app-backdrop')).toHaveAttribute('aria-hidden', 'true')
  })

  it('indexes staggered children', () => {
    render(
      <Stagger>
        <div data-testid="a" />
        <div data-testid="b" />
      </Stagger>,
    )
    expect(screen.getByTestId('b').style.getPropertyValue('--fx-i')).toBe('1')
  })

  it('renders stat chips and labelled round buttons', () => {
    render(
      <div>
        <StatChip label="Uptime" value="12 d" />
        <IconButton label="Zoom in" active />
      </div>,
    )
    expect(screen.getByText('Uptime')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Zoom in' })).toHaveAttribute('aria-pressed', 'true')
  })
})
