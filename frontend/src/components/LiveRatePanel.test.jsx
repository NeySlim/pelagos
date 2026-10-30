// SPDX-License-Identifier: Apache-2.0
// The time axis shows only under a chart; while counters are collected it keeps its
// height but stays invisible.
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { LiveRatePanel } from './LiveRatePanel'

const live = vi.hoisted(() => ({ points: [] }))
vi.mock('../hooks/useLiveRates', () => ({ useLiveRates: () => ({ dns: { points: live.points } }) }))

const target = { key: 'dns' }

describe('LiveRatePanel', () => {
  it('hides the time axis while it collects counters', () => {
    live.points = [{ t: 1, v: 3 }]
    render(<LiveRatePanel target={target} title="Queries" />)
    expect(screen.getByTestId('live-rate-collecting')).toBeInTheDocument()
    expect(screen.getByTestId('live-rate-axis')).toHaveClass('invisible')
  })

  it('says the curve waits for a second sample once the rate is known', async () => {
    await import('../i18n')
    live.points = [{ t: 1, v: 14 }]
    render(<LiveRatePanel target={target} title="Queries" />)
    expect(screen.getByTestId('live-rate-collecting')).toHaveTextContent('Curve from the next sample')
    expect(screen.getByTestId('live-rate-collecting')).not.toHaveTextContent('Collecting')
  })

  it('shows the time axis under the chart', () => {
    live.points = [{ t: 1, v: 3 }, { t: 2, v: 4 }]
    render(<LiveRatePanel target={target} title="Queries" />)
    expect(screen.queryByTestId('live-rate-collecting')).not.toBeInTheDocument()
    expect(screen.getByTestId('live-rate-axis')).not.toHaveClass('invisible')
  })
})
