// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import InstallPage from './InstallPage'
import { api } from '../../services/api'

vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ modules: { dhcpv6: true, advanced_editor: true } }) }))
vi.mock('../../services/api', () => {
  const api = {
    install: { detect: vi.fn(), plan: vi.fn(), importPlan: vi.fn() },
    plans: { apply: vi.fn(), get: vi.fn(), rollback: vi.fn() },
    jobs: { get: vi.fn() },
  }
  return { api, default: api }
})

const engine = (installed) => ({ installed, version: installed ? '9.20.11' : null, service: installed ? 'named.service' : null, running: installed, config: installed ? '/etc/bind/named.conf' : null })
const detect = {
  distro: { id: 'debian', version_id: '13', name: 'Debian GNU/Linux 13', package_manager: 'apt' },
  engines: { bind: engine(true), kea4: engine(true), kea6: engine(false), d2: engine(false) },
  pelagos: { include_present: false, sockets_ok: false, keys_present: false },
}

function plan(scope) {
  return {
    id: 'PLAN1', created_at: '2026-10-24T10:00:00Z', created_by: 'admin', node_id: 'n1', scope, engine: null,
    summary: `${scope} bind, kea4`, changes: [{ op: 'replace', target: `${scope}/bind`, before: null, after: null, node_ids: [] }],
    diff: '--- a/named.conf\n+++ b/named.conf\n@@ -1 +1,2 @@\n include "a";\n+include "/etc/bind/pelagos/pelagos.conf";\n',
    preconditions: [], validations: [{ ok: true, tool: 'named-checkconf', output: '', node_id: 'n1' }], target_node_ids: ['n1'],
    requires_confirmation: false, state: 'validated', expires_at: new Date(Date.now() + 600000).toISOString(), error: null,
  }
}

const renderPage = () => render(<MemoryRouter><InstallPage /></MemoryRouter>)

describe('InstallPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.install.detect.mockResolvedValue(detect)
  })

  it('shows what detection found', async () => {
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('install-engine-row')).toHaveLength(4))
    expect(screen.getByTestId('install-detect')).toHaveTextContent('Debian GNU/Linux 13')
    expect(screen.getByTestId('install-checks')).toHaveTextContent('Pelagos include lines in named.conf')
  })

  it('walks the import wizard and applies the plan as a job', async () => {
    api.install.importPlan.mockResolvedValue(plan('import'))
    api.plans.apply.mockResolvedValue({ id: 'J1', plan_id: 'PLAN1', state: 'running', progress: 40, steps: [{ name: 'add the include line', state: 'running' }], created_at: '', finished_at: null, error: null })
    renderPage()
    await screen.findByTestId('install-wizard')
    // Import is suggested because engines are installed.
    expect(screen.getByTestId('wizard-mode-import')).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByTestId('wizard-next'))
    const kea6 = screen.getByTestId('wizard-engine-kea6').querySelector('input')
    expect(kea6).toBeDisabled()
    const kea4 = screen.getByTestId('wizard-engine-kea4').querySelector('input')
    expect(kea4).toBeChecked()
    fireEvent.click(kea4)
    fireEvent.click(screen.getByTestId('wizard-next'))
    expect(screen.getByTestId('wizard-review')).toHaveTextContent('BIND 9 (DNS)')
    fireEvent.click(screen.getByTestId('wizard-build'))
    await waitFor(() => expect(api.install.importPlan).toHaveBeenCalledWith(['bind']))
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('import bind, kea4')
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(api.plans.apply).toHaveBeenCalledWith('PLAN1', false))
    expect(await screen.findByTestId('plan-job')).toHaveTextContent('add the include line')
  })

  it('asks for the package source when installing and blocks D2 without Kea', async () => {
    api.install.plan.mockResolvedValue(plan('install'))
    renderPage()
    await screen.findByTestId('install-wizard')
    fireEvent.click(screen.getByTestId('wizard-mode-install'))
    fireEvent.click(screen.getByTestId('wizard-next'))
    // Missing engines here are kea6 and d2; d2 is proposed, kea4 is installed.
    expect(screen.getByTestId('wizard-engine-bind').querySelector('input')).toBeDisabled()
    expect(screen.getByTestId('wizard-engine-d2').querySelector('input')).toBeChecked()
    fireEvent.click(screen.getByTestId('wizard-next'))
    fireEvent.click(screen.getByTestId('wizard-source-isc'))
    expect(screen.getByTestId('wizard-series')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Kea 3.0'))
    fireEvent.click(screen.getByTestId('wizard-next'))
    fireEvent.click(screen.getByTestId('wizard-build'))
    await waitFor(() => expect(api.install.plan).toHaveBeenCalledWith({ engines: ['d2'], source: 'isc', isc_series: '3.0' }))
  })

  it('does not go past the engines step without an engine', async () => {
    renderPage()
    await screen.findByTestId('install-wizard')
    fireEvent.click(screen.getByTestId('wizard-next'))
    fireEvent.click(screen.getByTestId('wizard-engine-bind').querySelector('input'))
    fireEvent.click(screen.getByTestId('wizard-engine-kea4').querySelector('input'))
    expect(screen.getByTestId('wizard-next')).toBeDisabled()
    expect(screen.getByTestId('wizard-error')).toHaveTextContent('Choose at least one engine')
  })
})
