// SPDX-License-Identifier: Apache-2.0
// Last unfiltered list per page, kept so a shared element can travel back into its row.
// Cleared on logout and when an item is deleted, so stale data never shows as live.
const cache = new Map()
export const getList = (key) => cache.get(key) ?? null
export const setList = (key, data) => cache.set(key, data)
export const clearLists = (key) => (key ? cache.delete(key) : cache.clear())
