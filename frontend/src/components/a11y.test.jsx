// SPDX-License-Identifier: Apache-2.0
// Accessible names of the shared form controls, page actions on mobile, utilization labels,
// node names in the plan preview.
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Input } from './Input'
import { Textarea } from './Textarea'
import { Select, FilterSelect } from './ui/Select'
import { SelectComponent } from './Select'
import { ToggleSwitch } from './ui/ToggleSwitch'
import TagsInput from './ui/TagsInput'
import { UnifiedPageHeader } from './ui/UnifiedPageHeader'
import { UtilizationBar } from './UtilizationBar'
import { PlanPreview } from './PlanPreview'
import { RouteStatus } from './RouteStatus'

describe('form controls have accessible names', () => {
  it('Input ties its label, error and helper text to the field', () => {
    const { rerender } = render(<Input label="Zone name" helperText="Fully qualified" />)
    const input = screen.getByLabelText('Zone name')
    expect(input.tagName).toBe('INPUT')
    expect(input).toHaveAccessibleDescription('Fully qualified')
    rerender(<Input label="Zone name" error="Required" />)
    expect(screen.getByLabelText('Zone name')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByLabelText('Zone name')).toHaveAccessibleDescription('Required')
  })

  it('Input keeps a caller id', () => {
    render(<Input label="Port" id="port-field" />)
    expect(screen.getByLabelText('Port')).toHaveAttribute('id', 'port-field')
  })

  it('Textarea ties its label', () => {
    render(<Textarea label="Comment" error="Too long" />)
    expect(screen.getByLabelText('Comment').tagName).toBe('TEXTAREA')
    expect(screen.getByLabelText('Comment')).toHaveAccessibleDescription('Too long')
  })

  it('Select triggers are named by their label or placeholder', () => {
    render(
      <>
        <Select label="Algorithm" options={[{ value: 'a', label: 'A' }]} value="a" onChange={() => {}} />
        <FilterSelect placeholder="All kinds" options={[{ value: 'p', label: 'Primary' }]} value="" onChange={() => {}} />
        <SelectComponent label="View" options={[{ value: 'v', label: 'default' }]} value="v" onChange={() => {}} />
      </>,
    )
    const combos = screen.getAllByRole('combobox')
    expect(combos[0]).toHaveAccessibleName(/Algorithm/)
    expect(combos[1]).toHaveAccessibleName('All kinds')
    expect(combos[2]).toHaveAccessibleName(/View/)
  })

  it('ToggleSwitch without a visible label uses ariaLabel; with one, the label', () => {
    render(
      <>
        <ToggleSwitch ariaLabel="Kea DHCPv4 ns1" checked={false} onChange={() => {}} />
        <ToggleSwitch label="Enabled" checked onChange={() => {}} />
      </>,
    )
    expect(screen.getByRole('switch', { name: 'Kea DHCPv4 ns1' })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Enabled' })).toBeInTheDocument()
  })

  it('TagsInput labels its input and each remove button', () => {
    const onChange = vi.fn()
    render(<TagsInput label="Forwarders" value={['192.0.2.53']} onChange={onChange} />)
    expect(screen.getByLabelText('Forwarders').tagName).toBe('INPUT')
    fireEvent.click(screen.getByRole('button', { name: 'Remove 192.0.2.53' }))
    expect(onChange).toHaveBeenCalledWith([])
  })
})

describe('UnifiedPageHeader on mobile', () => {
  it('keeps the page actions reachable', () => {
    render(<UnifiedPageHeader title="Subnets" isMobile actions={<button type="button">New subnet</button>} />)
    expect(screen.getByRole('button', { name: 'New subnet' })).toBeInTheDocument()
    expect(screen.queryByRole('heading')).not.toBeInTheDocument()
  })

  it('renders nothing extra when there are no actions', () => {
    const { container } = render(<UnifiedPageHeader title="Subnets" isMobile />)
    expect(container.querySelector('[data-testid="page-actions-mobile"]')).toBeNull()
  })
})

describe('UtilizationBar', () => {
  it('never shows 0% for a used pool and names its progress bar', () => {
    render(<UtilizationBar assigned={1} total={256} label="192.0.2.10 - 192.0.2.250" />)
    expect(screen.getByText('<1%')).toBeInTheDocument()
    const bar = screen.getByRole('progressbar', { name: '192.0.2.10 - 192.0.2.250' })
    expect(bar).toHaveAttribute('aria-valuetext', '<1% (1/256)')
  })

  it('has a default name', () => {
    render(<UtilizationBar assigned={0} total={10} />)
    expect(screen.getByRole('progressbar', { name: 'Utilization' })).toBeInTheDocument()
    expect(screen.getByText('0%')).toBeInTheDocument()
  })
})

describe('PlanPreview node names', () => {
  it('shows names instead of node ids', () => {
    const plan = {
      id: '01JBPLAN0000000000000000AA',
      scope: 'dns.rrset',
      state: 'validated',
      summary: 's',
      created_by: 'alice',
      changes: [{ op: 'add', target: 't', node_ids: ['01NODEA'] }],
      preconditions: [],
      validations: [{ ok: true, tool: 'named-checkconf', node_id: '01NODEB' }],
      target_node_ids: ['01NODEA', '01NODEB'],
      expires_at: new Date(Date.now() + 60000).toISOString(),
    }
    const names = { '01NODEA': 'ns1', '01NODEB': 'ns2' }
    render(<PlanPreview plan={plan} nodeName={(id) => names[id] || id} />)
    expect(screen.getByTestId('plan-target-nodes')).toHaveTextContent('Nodes: ns1, ns2')
    expect(screen.getByTestId('plan-changes')).toHaveTextContent('[ns1]')
    expect(screen.queryByText(/01NODEA/)).not.toBeInTheDocument()
  })
})

describe('RouteStatus', () => {
  it('explains a forbidden page and offers the dashboard', () => {
    render(
      <MemoryRouter>
        <RouteStatus kind="forbidden" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('alert')).toHaveTextContent('Access denied')
    expect(screen.getByRole('button', { name: 'Back to the dashboard' })).toBeInTheDocument()
  })
})
