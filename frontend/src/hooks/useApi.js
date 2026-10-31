// SPDX-License-Identifier: Apache-2.0
// Small data-fetching hook: runs an async function, tracks loading and error,
// refetches when `deps` change, ignores results of superseded calls. A transient GET
// failure (err.retryable, see apiClient) is retried in the background with a growing
// delay, and at once when the window regains focus, the browser goes online or the
// WebSocket reconnects; the error stays shown until a retry succeeds.
import { useCallback, useEffect, useRef, useState } from 'react'

export const RETRY_DELAYS = [5000, 10000, 20000, 30000, 60000]
export const RECONNECTED_EVENT = 'pelagos:reconnected'

export function useApi(fn, deps = [], { enabled = true, initialData = null } = {}) {
  const [data, setData] = useState(initialData)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(Boolean(enabled))
  const seq = useRef(0)
  const fnRef = useRef(fn)
  fnRef.current = fn

  // quiet: a background retry, which keeps the current error on screen while it runs.
  const run = useCallback(async ({ quiet = false } = {}) => {
    const id = ++seq.current
    if (!quiet) {
      setLoading(true)
      setError(null)
    }
    try {
      const result = await fnRef.current()
      if (id === seq.current) {
        setData(result)
        if (quiet) setError(null)
      }
      return result
    } catch (err) {
      if (id === seq.current) setError(err)
      return undefined
    } finally {
      if (id === seq.current && !quiet) setLoading(false)
    }
  }, [])
  const refetch = useCallback(() => run(), [run])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return undefined
    }
    run()
    return () => {
      seq.current += 1
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, run, ...deps])

  useAutoRetry(enabled && Boolean(error?.retryable), error, run)

  return { data, error, loading, refetch, setData }
}

// While `active`, calls run({ quiet: true }) after RETRY_DELAYS (the last one repeats) and
// on focus, online or WebSocket reconnection. A new `error` object is a failed retry.
function useAutoRetry(active, error, run) {
  const attempts = useRef(0)
  useEffect(() => {
    if (!error) attempts.current = 0
  }, [error])
  useEffect(() => {
    if (!active) return undefined
    const visible = () => typeof document === 'undefined' || document.visibilityState !== 'hidden'
    let done = false
    const fire = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      attempts.current += 1
      run({ quiet: true })
    }
    const delay = RETRY_DELAYS[Math.min(attempts.current, RETRY_DELAYS.length - 1)]
    // A hidden tab waits for the visibilitychange below instead of polling.
    const timer = setTimeout(() => visible() && fire(), delay)
    const onVisible = () => visible() && fire()
    window.addEventListener('focus', fire)
    window.addEventListener('online', fire)
    window.addEventListener(RECONNECTED_EVENT, fire)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      done = true
      clearTimeout(timer)
      window.removeEventListener('focus', fire)
      window.removeEventListener('online', fire)
      window.removeEventListener(RECONNECTED_EVENT, fire)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [active, error, run])
}

// Paginated variant: keeps page/perPage/query state and calls fn({ page, per_page, ...filters }).
export function usePaginatedApi(fn, { perPage = 50, filters = {}, enabled = true } = {}) {
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(perPage)
  const filterKey = JSON.stringify(filters)
  useEffect(() => {
    setPage(1)
  }, [filterKey])
  const query = useApi(() => fn({ page, per_page: size, ...filters }), [page, size, filterKey], { enabled })
  return {
    ...query,
    items: query.data?.items || [],
    total: query.data?.total ?? query.data?.items?.length ?? 0,
    meta: query.data?.meta || {},
    page,
    perPage: size,
    setPage,
    setPerPage: (n) => {
      setSize(n)
      setPage(1)
    },
  }
}
