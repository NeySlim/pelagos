// SPDX-License-Identifier: Apache-2.0
// Animation preference (full, reduced, off) and ambient backgrounds (on, off), stored with
// the other user preferences and resolved against prefers-reduced-motion and page
// visibility. The resolved level is written as data-motion, the ambient choice as
// data-ambient on documentElement, so CSS effects follow them too.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { getPreferences, persistPreference, subscribePreferences } from '../stores/preferencesStore'
import {
  AMBIENT_MODES,
  ANIMATION_LEVELS,
  DEFAULT_AMBIENT,
  DEFAULT_ANIMATIONS,
  ambientRunning,
  loopsAllowed,
  normalizeAmbient,
  normalizeAnimations,
  resolveMotionLevel,
} from '../lib/motion'

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
  ambient: DEFAULT_AMBIENT,
  setAmbient: () => {},
  level: 'full',
  hidden: false,
  loops: true,
  ambientRunning: true,
  levels: ANIMATION_LEVELS,
  ambientModes: AMBIENT_MODES,
}

const MotionContext = createContext(fallback)

export function MotionProvider({ children }) {
  const [animations, setAnimationsState] = useState(() => normalizeAnimations(getPreferences().animations))
  const [ambient, setAmbientState] = useState(() => normalizeAmbient(getPreferences().ambient))
  const [reduced, setReduced] = useState(systemReduced)
  const [hidden, setHidden] = useState(pageHidden)

  useEffect(() => {
    const apply = (prefs) => {
      if (prefs.animations !== undefined) setAnimationsState(normalizeAnimations(prefs.animations))
      if (prefs.ambient !== undefined) setAmbientState(normalizeAmbient(prefs.ambient))
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
    root.dataset.ambient = ambient
    if (hidden) root.dataset.pageHidden = ''
    else delete root.dataset.pageHidden
  }, [level, ambient, hidden])

  const setAnimations = useCallback((value) => {
    const next = normalizeAnimations(value)
    setAnimationsState(next)
    persistPreference('animations', next)
  }, [])

  const setAmbient = useCallback((value) => {
    const next = normalizeAmbient(value)
    setAmbientState(next)
    persistPreference('ambient', next)
  }, [])

  const value = useMemo(
    () => ({
      animations,
      setAnimations,
      ambient,
      setAmbient,
      level,
      hidden,
      loops: loopsAllowed(level, hidden),
      ambientRunning: ambientRunning(level, ambient, hidden),
      levels: ANIMATION_LEVELS,
      ambientModes: AMBIENT_MODES,
    }),
    [animations, setAnimations, ambient, setAmbient, level, hidden],
  )
  return <MotionContext.Provider value={value}>{children}</MotionContext.Provider>
}

export function useMotion() {
  return useContext(MotionContext)
}

// The resolved level ('full', 'reduced' or 'off'): what every animated component checks.
export function useMotionLevel() {
  return useContext(MotionContext).level
}

// True while ambient backgrounds may move (full level, switched on, page visible).
export function useAmbient() {
  return useContext(MotionContext).ambientRunning
}
