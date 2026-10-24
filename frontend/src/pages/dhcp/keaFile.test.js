// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest'

vi.mock('../../services/api', () => ({
  api: {
    dhcp: { adoptPlan: vi.fn(async (family, source) => ({ family, source })) },
    d2: { adoptPlan: vi.fn(async (source) => ({ family: 'd2', source })) },
  },
}))

import { adoptCall, divergedFiles, fileAlertEngine } from './keaFile'
import { nextCursor, previousCursor } from './lib'

describe('kea file divergence', () => {
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
    expect(await adoptCall('v6', 'file')).toEqual({ family: 'v6', source: 'file' })
    expect(await adoptCall('d2', 'running')).toEqual({ family: 'd2', source: 'running' })
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
