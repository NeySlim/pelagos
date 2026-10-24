// SPDX-License-Identifier: Apache-2.0
// The shared chrome renders through the motion primitives, so every page picks up the
// staggered entry, status dots, counting stats and round icon buttons.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge } from './Badge'
import { StatusIndicator } from './StatusIndicator'
import { PageLayout } from './PageLayout'
import { DetailGrid, DetailField, DetailHeader } from './DetailCard'
import { RichStatsBar } from './ui/RichStatsBar'
import { Modal } from './Modal'
import { Card } from './Card'

describe('shared components use the motion primitives', () => {
  it('Badge and StatusIndicator dots are StatusDots gated by fx classes', () => {
    render(
      <div>
        <Badge variant="warning" dot pulse>degraded</Badge>
        <StatusIndicator status="online" pulse>up</StatusIndicator>
      </div>,
    )
    const [badgeDot, indicatorDot] = screen.getAllByTestId('status-dot')
    expect(badgeDot).toHaveClass('ui-badge-dot', 'fx-tone-warning', 'fx-dot-pulse')
    expect(indicatorDot).toHaveClass('fx-tone-success', 'fx-dot-pulse')
    expect(document.querySelector('.animate-ping')).toBeNull()
  })

  it('PageLayout staggers the page children', () => {
    render(
      <PageLayout title="Zones">
        <div data-testid="first" />
        <div data-testid="second" />
      </PageLayout>,
    )
    expect(screen.getByTestId('page-stagger')).toHaveClass('fx-stagger', 'contents')
    expect(screen.getByTestId('second').style.getPropertyValue('--fx-i')).toBe('1')
  })

  it('DetailGrid staggers its fields, DetailHeader stats are counting chips', () => {
    const { container } = render(
      <div>
        <DetailHeader title="example.lan." stats={[{ label: 'Records', value: 12 }, { label: 'Serial', value: 'n/a' }]} />
        <DetailGrid>
          <DetailField label="a" value="1" />
          <DetailField label="b" value="2" />
        </DetailGrid>
      </div>,
    )
    expect(container.querySelector('dl')).toHaveClass('fx-stagger')
    const stats = screen.getByTestId('detail-stats')
    expect(stats.querySelectorAll('.ui-stat-chip')).toHaveLength(2)
    expect(stats.querySelector('.fx-count .sr-only')).toHaveTextContent('12')
    expect(screen.getByText('n/a')).toBeInTheDocument()
  })

  it('RichStatsBar counts numeric values inside a stagger', () => {
    render(<RichStatsBar stats={[{ label: 'Zones', value: 7 }]} />)
    const bar = screen.getByTestId('rich-stats-bar')
    expect(bar).toHaveClass('fx-stagger')
    expect(bar.querySelector('.fx-count .sr-only')).toHaveTextContent('7')
  })

  it('Modal close is a named round IconButton', () => {
    render(<Modal open title="Edit zone example.lan." onClose={() => {}}>body</Modal>)
    const close = screen.getByRole('button', { name: 'Close' })
    expect(close).toHaveClass('ui-icon-button')
  })

  it('display titles that carry identifiers keep their case', () => {
    render(
      <div>
        <PageLayout title="example.lan." />
        <Card.Header title="Records" />
      </div>,
    )
    expect(screen.getByRole('heading', { name: 'example.lan.' })).toHaveClass('ui-title-literal')
    expect(screen.getByRole('heading', { name: 'Records' })).toHaveClass('ui-title-static')
  })
})
