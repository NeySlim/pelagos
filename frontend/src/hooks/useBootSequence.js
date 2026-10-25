// SPDX-License-Identifier: Apache-2.0
// The instrument lights up once per session: html.boot is set on the first shell mount
// of a browser session and cleared after the cascade, so later navigations never replay
// it. Nothing happens at motion level off.
import { useEffect, useState } from 'react'
import { useMotionLevel } from '../contexts/MotionContext'

export const BOOT_KEY = 'pelagos-boot'
export const BOOT_MS = 1000

function seen() {
  try {
    return sessionStorage.getItem(BOOT_KEY) === '1'
  } catch {
    return true // no storage: skip the sequence rather than replay it on every load
  }
}

export function useBootSequence() {
  const level = useMotionLevel()
  // Decided once, from storage only, so a double mount (StrictMode) keeps the decision.
  const [boot] = useState(() => !seen())
  useEffect(() => {
    if (!boot) return undefined
    try {
      sessionStorage.setItem(BOOT_KEY, '1')
    } catch {
      // private browsing: the class still runs this once
    }
    if (level === 'off') return undefined
    const root = document.documentElement
    root.classList.add('boot')
    const timer = setTimeout(() => root.classList.remove('boot'), BOOT_MS)
    return () => {
      clearTimeout(timer)
      root.classList.remove('boot')
    }
  }, [boot]) // eslint-disable-line react-hooks/exhaustive-deps
  return boot
}
