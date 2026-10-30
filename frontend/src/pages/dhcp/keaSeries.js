// SPDX-License-Identifier: Apache-2.0
export const KIND = 'kea_series_obsolete'

// One line per open alert: node, series and end of life (null when ISC gave no date).
export function obsoleteSeries(items) {
  return (items || [])
    .filter((a) => a?.kind === KIND && a.state === 'open')
    .map((a) => ({ id: a.id, nodeId: a.node_id, series: a.details?.series || '?', eol: a.details?.eol || null }))
}

// One line per series for the whole cluster: the nodes that run it, the alert ids behind it.
export function seriesGroups(rows) {
  const groups = new Map()
  for (const r of rows || []) {
    const key = `${r.series}|${r.eol || ''}`
    if (!groups.has(key)) groups.set(key, { key, series: r.series, eol: r.eol, nodeIds: [], ids: [] })
    const g = groups.get(key)
    if (!g.nodeIds.includes(r.nodeId)) g.nodeIds.push(r.nodeId)
    g.ids.push(r.id)
  }
  return [...groups.values()]
}
