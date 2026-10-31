// SPDX-License-Identifier: Apache-2.0
// React.lazy whose chunk import is tried again after a network failure, so a page opened
// while the node blinks still loads. Chunks gone after an upgrade fail for good: the route
// error element (App.jsx) then reloads the app once the node answers.
import { lazy } from 'react'

export const IMPORT_RETRY_DELAYS = [500, 1500, 3000]

export async function retryImport(load, delays = IMPORT_RETRY_DELAYS) {
  let last
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await load()
    } catch (err) {
      last = err
      if (attempt >= delays.length) throw last
      await new Promise((resolve) => setTimeout(resolve, delays[attempt]))
    }
  }
}

export function lazyPage(load) {
  return lazy(() => retryImport(load))
}

// What browsers throw when a dynamic import cannot fetch its module.
export function isChunkError(err) {
  const text = String(err?.message || err || '')
  return /dynamically imported module|Importing a module script failed|error loading dynamically imported module|Loading chunk/i.test(text)
}
