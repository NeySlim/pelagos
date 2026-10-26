// SPDX-License-Identifier: Apache-2.0
// Hand over to Pelagos: statements set in the user's own named.conf files that a plan can
// move into the managed files. The server lists them with the nodes that have each one.

// One replace change per item; the plan leaves "# moved to <file> by Pelagos" in the user file.
export const handoverChanges = (items) =>
  items.map((item) => ({ op: 'replace', target: item.target, before: null, after: { comment: true }, node_ids: [] }))

const nodeKey = (item) => [...(item.nodes || [])].sort().join(',')

// A plan runs on one set of nodes: the largest group of items sharing it goes first, the rest
// stay listed for the next click.
export function handoverBatch(items) {
  const groups = new Map()
  for (const item of items) {
    const key = nodeKey(item)
    groups.set(key, [...(groups.get(key) || []), item])
  }
  let best = []
  for (const group of groups.values()) if (group.length > best.length) best = group
  return best
}

// Items of the given kinds ('options', 'acls', 'keys', 'zones'), optionally limited to a name list.
export const handoverItems = (data, kinds, names) =>
  (data?.items || []).filter((i) => kinds.includes(i.kind) && (!names || names.includes(i.name)))

export const handoverNodes = (items) => [...new Set(items.flatMap((i) => i.nodes || []))]

export const zoneHandover = (data, zone) =>
  handoverItems(data, ['zones']).find((i) => i.name === zone?.name && (i.view || '_default') === (zone?.view || '_default'))
