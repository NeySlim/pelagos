// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest'

vi.mock('../../services/api', () => ({
  api: {
    dhcp: { adoptPlan: vi.fn(async (family, source, node_id) => ({ family, source, node_id })) },
    d2: { adoptPlan: vi.fn(async (source, node_id) => ({ family: 'd2', source, node_id })) },
  },
}))

import { adoptCall, adoptPlace, affectsFileStatus, divergedFiles, fileAlertEngine, syntaxAlertEngine, warnedFiles } from './keaFile'
import { nextCursor, previousCursor } from './lib'

describe('kea file divergence', () => {
  it('offers adopt only on the node that holds the file, never before the nodes are known', () => {
    expect(adoptPlace({ node_id: 'a' }, undefined)).toBe('unknown')
    expect(adoptPlace({ node_id: 'a' }, 'a')).toBe('here')
    expect(adoptPlace({ node_id: 'b' }, 'a')).toBe('other')
  })

  it('keeps only the files that disagree', () => {
    expect(divergedFiles([{ node_id: 'a', diverged: true }, { node_id: 'b', diverged: false }, null])).toEqual([{ node_id: 'a', diverged: true }])
    expect(divergedFiles(undefined)).toEqual([])
  })

  it('maps a file alert to its engine and nothing else', () => {
    expect(fileAlertEngine({ kind: 'config_divergence', subject: 'kea4:config-file' })).toBe('v4')
    expect(fileAlertEngine({ kind: 'config_divergence', subject: 'kea6:config-file' })).toBe('v6')
    expect(fileAlertEngine({ kind: 'config_divergence', subject: 'd2:config-file' })).toBe('d2')
    expect(fileAlertEngine({ kind: 'config_divergence', subject: 'kea4:config' })).toBeNull()
    expect(fileAlertEngine({ kind: 'pool_full', subject: 'kea4:config-file' })).toBeNull()
    expect(fileAlertEngine(null)).toBeNull()
  })

  it('builds the adopt plan of the right engine', async () => {
    expect(await adoptCall('v6', 'file')).toEqual({ family: 'v6', source: 'file', node_id: undefined })
    expect(await adoptCall('d2', 'running')).toEqual({ family: 'd2', source: 'running', node_id: undefined })
    expect(await adoptCall('v4', 'file', 'b')).toEqual({ family: 'v4', source: 'file', node_id: 'b' })
    expect(await adoptCall('d2', 'file', 'b')).toEqual({ family: 'd2', source: 'file', node_id: 'b' })
  })
})

describe('lease cursor', () => {
  it('pushes the next cursor and pops back to the first page', () => {
    let stack = [null]
    stack = nextCursor(stack, '192.0.2.100')
    stack = nextCursor(stack, '192.0.2.200')
    expect(stack).toEqual([null, '192.0.2.100', '192.0.2.200'])
    expect(nextCursor(stack, null)).toBe(stack)
    stack = previousCursor(previousCursor(stack))
    expect(stack).toEqual([null])
    expect(previousCursor(stack)).toEqual([null])
  })
})

describe('affectsFileStatus', () => {
  it('only reacts to this engine file divergence alerts', () => {
    const file = { topic: 'alerts', event: 'opened', data: { kind: 'config_divergence', subject: 'kea4:config-file' } }
    expect(affectsFileStatus(file, 'v4')).toBe(true)
    expect(affectsFileStatus(file, 'd2')).toBe(false)
    expect(affectsFileStatus({ data: { kind: 'pool_full', subject: 'kea4:subnet:1:pool:p' } }, 'v4')).toBe(false)
    expect(affectsFileStatus({}, 'v4')).toBe(false)
  })
})

describe('kea syntax warnings', () => {
  it('lists the files with warnings and the engine a warning alert is about', () => {
    const items = [{ node_id: 'a', syntax_warnings: [{ path: '/etc/kea/k.conf', line: 56, column: 3 }] }, { node_id: 'b', syntax_warnings: [] }, { node_id: 'c' }]
    expect(warnedFiles(items).map((i) => i.node_id)).toEqual(['a'])
    expect(syntaxAlertEngine({ kind: 'config_syntax_warning', subject: 'kea6:config-syntax' })).toBe('v6')
    expect(syntaxAlertEngine({ kind: 'config_divergence', subject: 'kea6:config-syntax' })).toBe(null)
    const warned = { topic: 'alerts', data: { kind: 'config_syntax_warning', subject: 'kea4:config-syntax' } }
    expect(affectsFileStatus(warned, 'v4')).toBe(true)
    expect(affectsFileStatus(warned, 'v6')).toBe(false)
  })
})
