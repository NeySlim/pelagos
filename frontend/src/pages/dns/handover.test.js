// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { handoverBatch, handoverChanges, handoverItems, zoneHandover } from './handover'

const item = (kind, name, nodes, view = null) => ({ kind, name, view, target: `handover/${kind}/${name}`, nodes })

describe('handover helpers', () => {
  const data = { items: [item('options', 'recursion', ['a', 'b']), item('options', 'max-ncache-ttl', ['b', 'a']), item('keys', 'k1', ['a']), item('zones', 'z.lan.', ['a'], '_default')] }

  it('filters by kind and name', () => {
    expect(handoverItems(data, ['options']).map((i) => i.name)).toEqual(['recursion', 'max-ncache-ttl'])
    expect(handoverItems(data, ['options'], ['recursion'])).toHaveLength(1)
  })

  it('batches the largest group of items that share their nodes', () => {
    const batch = handoverBatch(data.items)
    expect(batch.map((i) => i.name)).toEqual(['recursion', 'max-ncache-ttl'])
  })

  it('builds one replace change per item that keeps a comment', () => {
    const changes = handoverChanges([data.items[2]])
    expect(changes).toEqual([{ op: 'replace', target: 'handover/keys/k1', before: null, after: { comment: true }, node_ids: [] }])
  })

  it('finds the handover of a zone by name and view', () => {
    expect(zoneHandover(data, { name: 'z.lan.', view: '_default' })?.kind).toBe('zones')
    expect(zoneHandover(data, { name: 'z.lan.', view: 'internal' })).toBeUndefined()
  })
})
