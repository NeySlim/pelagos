// SPDX-License-Identifier: Apache-2.0
// Previous backup of the same engine, node and first file, searched on the
// server (not only in the page on screen) so the detail can show a diff.

export const PREVIOUS_PER_PAGE = 100
export const PREVIOUS_MAX_PAGES = 10

export async function findPreviousBackup(item, fetchPage) {
  const first = item.files?.[0]
  for (let page = 1; page <= PREVIOUS_MAX_PAGES; page += 1) {
    const res = await fetchPage({ engine: item.engine, node_id: item.node_id, sort: 'ts', order: 'desc', page, per_page: PREVIOUS_PER_PAGE })
    const items = res?.items || []
    const older = items
      .filter((i) => i.id !== item.id && i.ts < item.ts && i.engine === item.engine && i.node_id === item.node_id && i.files?.[0] === first)
      .sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0))
    if (older.length) return older[0]
    const total = res?.total ?? 0
    if (items.length < PREVIOUS_PER_PAGE || page * PREVIOUS_PER_PAGE >= total) return null
  }
  return null
}
