// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { NotificationProvider } from '../../contexts/NotificationContext'
import { OptionForm } from './OptionsPage'
import { ClassForm } from './ClassesPage'

vi.mock('../../services/api', () => ({ api: { dhcp: {} }, default: { dhcp: {} } }))

const wrap = (ui) => render(<MemoryRouter><NotificationProvider>{ui}</NotificationProvider></MemoryRouter>)
const flow = { build: vi.fn(), building: false }
const preview = () => screen.getByRole('button', { name: 'Preview the plan' })

beforeEach(() => vi.clearAllMocks())

describe('unchanged guard with null flags from Kea', () => {
  it('OptionForm stays disabled on an option whose flags are null, and wakes on a change', () => {
    const option = { name: 'routers', code: 3, space: 'dhcp4', data: '192.0.2.1', csv_format: null, always_send: null, never_send: null, raw: {} }
    wrap(<OptionForm family="v4" option={option} existing={[option]} flow={flow} onClose={vi.fn()} />)
    expect(preview()).toBeDisabled()
    const boxes = screen.getAllByRole('checkbox')
    fireEvent.click(boxes[1])
    expect(preview()).toBeEnabled()
    fireEvent.click(boxes[1])
    expect(preview()).toBeDisabled()
  })

  it('ClassForm stays disabled on a class with a null additional-list flag', () => {
    const cls = { name: 'pxe', test: null, only_in_additional_list: null, options: [], option_def: [], raw: {}, user_context: {} }
    wrap(<ClassForm family="v4" cls={cls} existing={[cls]} flow={flow} onClose={vi.fn()} />)
    expect(preview()).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    expect(preview()).toBeEnabled()
    fireEvent.click(screen.getByRole('checkbox'))
    expect(preview()).toBeDisabled()
  })
})
