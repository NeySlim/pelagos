// SPDX-License-Identifier: Apache-2.0
// Animation preference (full, reduced, off) stored with the other user preferences,
// resolved against prefers-reduced-motion and page visibility. The resolved level is
// written as data-motion on documentElement so CSS effects follow it too.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { getPreferences, persistPreference, subscribePreferences } from '../stores/preferencesStore'
import { ANIMATION_LEVELS, DEFAULT_ANIMATIONS, loopsAllowed, normalizeAnimations, resolveMotionLevel } from '../lib/motion'

const REDUCED_QUERY = '(prefers-reduced-motion: reduce)'

function systemReduced() {
  if (typeof window === 'undefined' || !window.matchMedia) return false
  return window.matchMedia(REDUCED_QUERY).matches
}

function pageHidden() {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden'
}

// Without a provider (isolated component tests) motion runs at full level.
const fallback = {
  animations: DEFAULT_ANIMATIONS,
  setAnimations: () => {},
  level: 'full',
  hidden: false,
  loops: true,
  levels: ANIMATION_LEVELS,
}

const MotionContext = createContext(fallback)

export function MotionProvider({ children }) {
  const [animations, setAnimationsState] = useState(() => normalizeAnimations(getPreferences().animations))
  const [reduced, setReduced] = useState(systemReduced)
  const [hidden, setHidden] = useState(pageHidden)

  useEffect(() => {
    const apply = (prefs) => {
      if (prefs.animations !== undefined) setAnimationsState(normalizeAnimations(prefs.animations))
    }
    return subscribePreferences(apply)
  }, [])

  useEffect(() => {
    if (!window.matchMedia) return undefined
    const query = window.matchMedia(REDUCED_QUERY)
    const update = () => setReduced(query.matches)
    update()
    query.addEventListener?.('change', update)
    return () => query.removeEventListener?.('change', update)
  }, [])

  useEffect(() => {
    const update = () => setHidden(pageHidden())
    document.addEventListener('visibilitychange', update)
    return () => document.removeEventListener('visibilitychange', update)
  }, [])

  const level = resolveMotionLevel(animations, reduced)

  useEffect(() => {
    const root = document.documentElement
    root.dataset.motion = level
    if (hidden) root.dataset.pageHidden = ''
    else delete root.dataset.pageHidden
  }, [level, hidden])

  const setAnimations = useCallback((value) => {
    const next = normalizeAnimations(value)
    setAnimationsState(next)
    persistPreference('animations', next)
  }, [])

  const value = useMemo(
    () => ({ animations, setAnimations, level, hidden, loops: loopsAllowed(level, hidden), levels: ANIMATION_LEVELS }),
    [animations, setAnimations, level, hidden],
  )
  return <MotionContext.Provider value={value}>{children}</MotionContext.Provider>
}

export function useMotion() {
  return useContext(MotionContext)
}
