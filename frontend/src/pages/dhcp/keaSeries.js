// SPDX-License-Identifier: Apache-2.0
export const KIND = 'kea_series_obsolete'

// One line per open alert: node, series and end of life (null when ISC gave no date).
export function obsoleteSeries(items) {
  return (items || [])
    .filter((a) => a?.kind === KIND && a.state === 'open')
    .map((a) => ({ id: a.id, nodeId: a.node_id, series: a.details?.series || '?', eol: a.details?.eol || null }))
}
