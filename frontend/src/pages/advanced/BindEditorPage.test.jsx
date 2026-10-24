// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import BindEditorPage from './BindEditorPage'
import { api } from '../../services/api'

let permissions = ['*']
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => permissions.includes('*') || permissions.includes(p) }) }))
vi.mock('../../services/api', () => {
  const api = {
    advanced: { bindGrammar: vi.fn(), bindTree: vi.fn() },
    dns: { configPlan: vi.fn() },
    nodes: { list: vi.fn() },
    plans: { apply: vi.fn(), get: vi.fn(), rollback: vi.fn() },
    jobs: { get: vi.fn() },
  }
  return { api, default: api }
})

const grammar = {
  version: '9.20',
  statements: [
    { name: 'options', contexts: ['toplevel'], args: 'block' },
    { name: 'directory', contexts: ['options'], args: 'quoted_string' },
    { name: 'recursion', contexts: ['options', 'view'], args: 'boolean' },
    { name: 'allow-recursion', contexts: ['options', 'view'], args: 'address_match_list' },
  ],
}
const tree = {
  files: [
    { path: '/etc/bind/named.conf.options', managed: false, statements: [{ name: 'options', value: null, line: 1, children: [{ name: 'directory', value: '"/var/cache/bind"', line: 2 }, { name: 'recursion', value: 'yes', line: 3 }] }] },
    { path: '/etc/bind/pelagos/keys.conf', managed: true, statements: [{ name: 'key', value: '"ddi-admin"', line: 1, children: [{ name: 'algorithm', value: 'hmac-sha256', line: 2 }] }] },
  ],
}

const statement = (name) => screen.getAllByTestId('bind-statement').find((el) => el.dataset.name === name)

describe('BindEditorPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    permissions = ['*']
    api.advanced.bindGrammar.mockResolvedValue(grammar)
    api.advanced.bindTree.mockResolvedValue(tree)
    api.nodes.list.mockResolvedValue({ items: [] })
  })

  it('edits a statement through its grammar form and builds a dns.config plan', async () => {
    api.dns.configPlan.mockResolvedValue({
      id: 'P1', created_at: '', created_by: 'admin', node_id: 'n1', scope: 'dns.config', engine: 'bind', summary: '1 configuration change(s)',
      changes: [{ op: 'replace', target: 'options/directory', before: null, after: null, node_ids: [] }], diff: '', preconditions: [],
      validations: [{ ok: true, tool: 'named-checkconf', output: '', node_id: 'n1' }], target_node_ids: ['n1'], requires_confirmation: false,
      state: 'validated', expires_at: new Date(Date.now() + 600000).toISOString(), error: null,
    })
    render(<BindEditorPage />)
    await waitFor(() => expect(statement('directory')).toBeTruthy())
    fireEvent.click(statement('directory'))
    expect(screen.getByTestId('grammar-info')).toHaveTextContent('directory quoted_string')
    fireEvent.change(screen.getByTestId('value-input'), { target: { value: '/var/lib/bind' } })
    fireEvent.click(screen.getByTestId('statement-save'))
    expect(screen.getByTestId('bind-changes')).toHaveTextContent('options/directory')
    expect(screen.getByTestId('bind-pending')).toHaveTextContent(/\+\s*directory "\/var\/lib\/bind";/)
    fireEvent.click(screen.getByTestId('bind-plan'))
    await waitFor(() =>
      expect(api.dns.configPlan).toHaveBeenCalledWith([{ op: 'replace', target: 'options/directory', before: '"/var/cache/bind"', after: '"/var/lib/bind"', node_ids: [] }], undefined),
    )
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('1 configuration change(s)')
  })

  it('adds a statement allowed in the block context', async () => {
    render(<BindEditorPage />)
    await waitFor(() => expect(statement('options')).toBeTruthy())
    const row = statement('options')
    fireEvent.click(within(row).getByTitle('Add a statement inside this block'))
    expect(screen.getByTestId('statement-add')).toHaveTextContent('New statement in context options')
  })

  it('keeps zones, keys and ACLs of managed files on their own screens', async () => {
    render(<BindEditorPage />)
    await waitFor(() => expect(statement('key')).toBeTruthy())
    fireEvent.click(statement('key'))
    expect(screen.getByTestId('bind-form')).toHaveTextContent('have their own screens')
    expect(screen.queryByTestId('statement-save')).not.toBeInTheDocument()
  })

  it('is read-only without write:dns.config', async () => {
    permissions = ['read:advanced']
    render(<BindEditorPage />)
    await waitFor(() => expect(statement('directory')).toBeTruthy())
    fireEvent.click(statement('directory'))
    expect(screen.queryByTestId('statement-save')).not.toBeInTheDocument()
    expect(screen.getByTestId('bind-plan')).toBeDisabled()
  })
})
