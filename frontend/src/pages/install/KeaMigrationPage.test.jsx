// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import KeaMigrationPage from './KeaMigrationPage'
import { api } from '../../services/api'
import { defaultTarget, fullyValidated, groupFindings, nodeEngines, obsoleteEngines, parseTarget } from './keaMigration'

vi.mock('../../services/api', () => {
  const api = { keaMigration: { overview: vi.fn(), analyze: vi.fn() } }
  return { api, default: api }
})

const engine = { version: '2.6.3', series: '2.6', source: 'distro', package: 'kea-dhcp4-server', maintained: false, eol: '2026-07-30', successor: '3.2' }
const overview = {
  nodes: [
    { node_id: 'n1', name: 'ns1', reachable: true, error: null, engines: { kea4: engine } },
    { node_id: 'n2', name: 'ns2', reachable: false, error: 'node ns2 is offline', engines: {} },
  ],
  targets: [
    { series: '3.2', source: 'isc', version: null, available: true, recommended: true },
    { series: '3.0', source: 'isc', version: null, available: true, recommended: false },
    { series: '3.0', source: 'backports', version: null, available: false, recommended: false, note: 'x' },
  ],
  analysis: null,
  current: null,
}
const finding = (severity, code, node_id, engine, params = {}) => ({
  severity, code, node_id, engine, path: 'Dhcp4', action: 'convert', reference: 'https://kb.isc.org/docs/kea-control-agent-migration',
  message: { key: `kea_migration.${code}`, params: { path: 'Dhcp4', ...params } },
})
const report = {
  id: 'R1', created_at: '2026-10-29T10:00:00Z', created_by: 'admin', series: '3.2', source: 'isc', target_version: '3.2.1-isc20260928103142',
  node_ids: ['n1', 'n2'],
  findings: [
    finding('converted', 'restrict_commands', 'n1', 'kea4'),
    finding('blocking', 'node_unreachable', 'n2', '', { node: 'ns2' }),
    finding('behavior', 'lease_cache', 'n1', 'kea4', { engine: 'kea4' }),
  ],
  diffs: { n1: { kea4: '--- a\n+++ b\n-  "require-client-classes": [ "voip" ]\n+  "evaluate-additional-classes": [ "voip" ]\n' } },
  packages: { n1: { remove: [{ name: 'kea-dhcp4-server', version: '2.6.3-1+deb13u1' }], install: [{ name: 'isc-kea-dhcp4', version: '3.2.1-isc20260928103142' }] } },
  validation: { n1: { kea4: { ok: true, mode: 'dry_run', output: '' } } },
  counts: { blocking: 1, converted: 1, behavior: 1, info: 0 },
  blocking: true,
  unreachable: ['n2'],
  outage_estimate_seconds: 30,
}

const renderPage = () => render(<MemoryRouter><KeaMigrationPage /></MemoryRouter>)

describe('keaMigration helpers', () => {
  it('chooses the recommended available target', () => {
    expect(defaultTarget(overview.targets)).toMatchObject({ series: '3.2', source: 'isc' })
    expect(defaultTarget([{ series: '3.0', source: 'isc', available: false }])).toBeNull()
    expect(parseTarget('3.0/backports')).toEqual({ series: '3.0', source: 'backports' })
    expect(parseTarget('')).toBeNull()
  })

  it('groups findings by severity then node', () => {
    const groups = groupFindings(report)
    expect(groups.map(([s]) => s)).toEqual(['blocking', 'converted', 'behavior'])
    expect(groups[0][1][0][0]).toBe('n2')
    expect(nodeEngines(report, 'n1')).toEqual(['kea4'])
    expect(fullyValidated(report)).toBe(true)
    expect(fullyValidated({ ...report, validation: { n1: { kea4: { ok: false, mode: 'skipped' } } } })).toBe(false)
    expect(obsoleteEngines(overview.nodes[0])).toEqual(['kea4'])
  })
})

describe('KeaMigrationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.keaMigration.overview.mockResolvedValue(overview)
  })

  it('shows the series of each node and the unreachable one', async () => {
    renderPage()
    const rows = await screen.findAllByTestId('kea-migration-node')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('2.6.3')
    expect(rows[0]).toHaveTextContent('2.6 no longer maintained since 2026-07-30')
    expect(rows[1]).toHaveTextContent('node ns2 is offline')
    expect(screen.getByTestId('kea-migration-obsolete-note')).toBeInTheDocument()
    expect(screen.getByTestId('kea-migration-none')).toBeInTheDocument()
    const select = screen.getByTestId('kea-migration-target-select')
    expect(select).toHaveValue('3.2/isc')
    expect(within(select).getByRole('option', { name: /backports/ })).toBeDisabled()
  })

  it('analyzes the chosen target and shows the report', async () => {
    api.keaMigration.analyze.mockResolvedValue(report)
    renderPage()
    fireEvent.change(await screen.findByTestId('kea-migration-target-select'), { target: { value: '3.0/isc' } })
    fireEvent.click(screen.getByTestId('kea-migration-analyze'))
    await screen.findByTestId('kea-migration-report')
    expect(api.keaMigration.analyze).toHaveBeenCalledWith({ series: '3.0', source: 'isc' })
    expect(screen.getByTestId('kea-migration-blocking')).toBeInTheDocument()
    const groups = screen.getAllByTestId('kea-migration-group')
    expect(groups.map((g) => g.dataset.severity)).toEqual(['blocking', 'converted', 'behavior'])
    expect(groups[0]).toHaveTextContent('node ns2 did not answer')
    expect(screen.getByTestId('kea-migration-outage')).toHaveTextContent('30 s')
    // Only the node that answered has details: validation, packages, diff.
    const details = screen.getAllByTestId('kea-migration-node-report')
    expect(details).toHaveLength(1)
    expect(within(details[0]).getByTestId('kea-migration-validation')).toHaveTextContent('checked')
    expect(within(details[0]).getByTestId('kea-migration-packages-remove')).toHaveTextContent('kea-dhcp4-server 2.6.3-1+deb13u1')
    expect(within(details[0]).getByTestId('kea-migration-diff')).toHaveTextContent('evaluate-additional-classes')
  })

  it('shows the kept analysis and an analysis error', async () => {
    api.keaMigration.overview.mockResolvedValue({ ...overview, analysis: { ...report, blocking: false, findings: [], counts: { blocking: 0 } } })
    api.keaMigration.analyze.mockRejectedValue(Object.assign(new Error('series and source must be one of'), { status: 400 }))
    renderPage()
    expect(await screen.findByTestId('kea-migration-ready')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('kea-migration-analyze'))
    await waitFor(() => expect(screen.getByTestId('kea-migration-error')).toBeInTheDocument())
  })
})
