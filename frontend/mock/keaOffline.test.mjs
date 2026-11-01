// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { partialApply } from './keaOffline.mjs'

class Problem extends Error {
  constructor(status, code, detail) {
    super(detail)
    this.status = status
    this.code = code
  }
}

const state = () => ({
  selfId: 'N1',
  offlineNodes: ['N2'],
  nodes: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }],
})
const plan = () => ({ id: 'P1', scope: 'dhcp.reservation', engine: 'kea4', target_node_ids: ['N1', 'N2'], requires_confirmation_reasons: [] })

describe('mock partial apply', () => {
  it('answers node_unreachable without partial', () => {
    try {
      partialApply(state(), plan(), { confirm: true }, Problem)
      throw new Error('no problem')
    } catch (err) {
      expect(err.code).toBe('node_unreachable')
      expect(err.extra).toMatchObject({ node_ids: ['N2'], node_names: ['ns2'], partial_allowed: true })
    }
  })

  it('narrows the plan and records the couple with partial', () => {
    const s = state()
    const p = plan()
    partialApply(s, p, { confirm: true, partial: true }, Problem)
    expect(p.target_node_ids).toEqual(['N1'])
    expect(p.skipped).toEqual([{ node_id: 'N2', reason: 'unreachable' }])
    expect(p.requires_confirmation_reasons).toContain('partial_apply')
    expect(s.keaPartials[0]).toMatchObject({ id: 'kea4:N1:N2', plan_count: 1 })
  })

  it('leaves plans that do not narrow alone', () => {
    const p = { ...plan(), scope: 'dhcp.config' }
    partialApply(state(), p, { confirm: true }, Problem)
    expect(p.target_node_ids).toEqual(['N1', 'N2'])
  })
})
