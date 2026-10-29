// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import KeaMigrationPage from './KeaMigrationPage'
import { api } from '../../services/api'
import { defaultTarget, fullyValidated, groupFindings, nodeEngines, obsoleteEngines, parseTarget, unusedFindings, usedCounts } from './keaMigration'

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

// kea6 of n1 is neither active nor enabled: its findings are info, apart, and gate nothing.
const unusedReport = {
  ...report,
  node_ids: ['n1'],
  unreachable: [],
  findings: [
    finding('converted', 'restrict_commands', 'n1', 'kea4'),
    { ...finding('info', 'hook_missing', 'n1', 'kea6', { library: 'libkea_sanitize_hostname.so', series: '3.2', source: 'isc' }), unused: true, severity_if_used: 'blocking', action: 'manual' },
    { ...finding('info', 'engine_unused', 'n1', 'kea6', { engine: 'kea6', node: 'ns1', unit: 'kea-dhcp6-server.service', active: 'inactive', enabled: 'disabled' }), unused: true, severity_if_used: 'info', action: 'none' },
  ],
  validation: { n1: { kea4: { ok: true, mode: 'dry_run', output: '' }, kea6: { ok: false, mode: 'dry_run', output: 'hook' } } },
  units: { n1: { kea4: { unit: 'kea-dhcp4-server.service', active: 'active', enabled: 'enabled', used: true }, kea6: { unit: 'kea-dhcp6-server.service', active: 'inactive', enabled: 'disabled', used: false } } },
  counts: { blocking: 0, converted: 1, behavior: 0, info: 2 },
  blocking: false,
  outage_estimate_seconds: 15,
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

  it('sets the findings of an unused daemon apart', () => {
    expect(groupFindings(unusedReport).map(([s]) => s)).toEqual(['converted'])
    const unused = unusedFindings(unusedReport)
    expect(unused).toHaveLength(1)
    expect(unused[0][1].map((f) => f.code)).toEqual(['hook_missing', 'engine_unused'])
    // The refused dry run of an unused daemon does not count as unchecked.
    expect(fullyValidated(unusedReport)).toBe(true)
    const used = { ...unusedReport, units: { n1: { ...unusedReport.units.n1, kea6: { used: true } } } }
    expect(fullyValidated(used)).toBe(false)
    // A node whose only daemon is unused is not "not validated" either.
    const alone = { ...unusedReport, validation: { n1: { kea6: unusedReport.validation.n1.kea6 } } }
    expect(fullyValidated(alone)).toBe(true)
    expect(usedCounts(unusedReport)).toEqual({ blocking: 0, converted: 1, behavior: 0, info: 0 })
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

  it('keeps the recommended target and says why none is available', async () => {
    const reason = { code: 'node_unreachable', node: 'ns2', error: 'node ns2 is offline' }
    const targets = overview.targets.map((x) => ({ ...x, available: false, reason }))
    api.keaMigration.overview.mockResolvedValue({ ...overview, targets })
    renderPage()
    expect(await screen.findByTestId('kea-migration-target-reason')).toHaveTextContent('ns2 does not answer or runs an older Pelagos release')
    expect(screen.getByTestId('kea-migration-target-select')).toHaveValue('3.2/isc')
    expect(screen.getByTestId('kea-migration-analyze')).toBeDisabled()
  })

  it('shows an unknown maintenance state as unknown', async () => {
    const node = { ...overview.nodes[0], engines: { kea4: { ...engine, maintained: null, eol: null } } }
    api.keaMigration.overview.mockResolvedValue({ ...overview, nodes: [node] })
    renderPage()
    expect(await screen.findByTestId('kea-migration-unknown')).toHaveTextContent('2.6: maintenance unknown')
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

  it('shows an unused daemon apart and not blocking', async () => {
    api.keaMigration.overview.mockResolvedValue({ ...overview, analysis: unusedReport })
    renderPage()
    expect(await screen.findByTestId('kea-migration-ready')).toBeInTheDocument()
    expect(screen.queryByTestId('kea-migration-blocking')).not.toBeInTheDocument()
    expect(screen.queryByTestId('kea-migration-not-validated')).not.toBeInTheDocument()
    expect(screen.getAllByTestId('kea-migration-group').map((g) => g.dataset.severity)).toEqual(['converted'])
    const unused = screen.getByTestId('kea-migration-unused')
    expect(unused).toHaveTextContent('Unused daemons')
    expect(unused).toHaveTextContent('kea6 on ns1 is not used (kea-dhcp6-server.service inactive, disabled)')
    expect(within(unused).getByTestId('kea-migration-if-used')).toHaveTextContent('Blocking if enabled')
    const badges = screen.getAllByTestId('kea-migration-validation')
    expect(badges.find((b) => b.dataset.engine === 'kea6')).toHaveTextContent('refused (not used)')
    expect(screen.getByTestId('kea-migration-outage')).toHaveTextContent('15 s')
  })
})
