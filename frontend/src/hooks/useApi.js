// SPDX-License-Identifier: Apache-2.0
// Small data-fetching hook: runs an async function, tracks loading and error,
// refetches when `deps` change, ignores results of superseded calls.
import { useCallback, useEffect, useRef, useState } from 'react'

export function useApi(fn, deps = [], { enabled = true, initialData = null } = {}) {
  const [data, setData] = useState(initialData)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(Boolean(enabled))
  const seq = useRef(0)
  const fnRef = useRef(fn)
  fnRef.current = fn

  const run = useCallback(async () => {
    const id = ++seq.current
    setLoading(true)
    setError(null)
    try {
      const result = await fnRef.current()
      if (id === seq.current) setData(result)
      return result
    } catch (err) {
      if (id === seq.current) setError(err)
      return undefined
    } finally {
      if (id === seq.current) setLoading(false)
    }
  }, [])

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

  return { data, error, loading, refetch: run, setData }
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
