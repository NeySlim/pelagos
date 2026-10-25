// SPDX-License-Identifier: Apache-2.0
// Nodes that were behind before this render: a serial of theirs that rises now came
// through a zone transfer (NOTIFY, then IXFR or AXFR), the one that rose first did not.
import { useEffect, useRef } from 'react'
import { laggingNodes } from './helpers'

export function useCatchUps(serials) {
  const lagging = useRef(new Set())
  const before = lagging.current
  useEffect(() => {
    lagging.current = new Set(laggingNodes(serials || {}))
  }, [serials])
  return before
}
