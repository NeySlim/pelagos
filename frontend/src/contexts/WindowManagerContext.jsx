// SPDX-License-Identifier: Apache-2.0
// Floating detail windows: open by (type, entityId), at most six, z-order by focus,
// tile and stack helpers. Pages register a renderer per type (see FloatingDetailWindow).
import { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'
import { useAuth } from './AuthContext'

const WindowManagerContext = createContext(null)

const MAX_WINDOWS = 6
const CASCADE_OFFSET = 30
const BASE_Z = 100
const PREFS_KEY = 'pelagos-window-prefs'
export const WINDOW_POS_PREFIX = 'pelagos-detail-'

function loadPrefs() {
  try {
    return JSON.parse(localStorage.getItem(PREFS_KEY)) || {}
  } catch {
    return {}
  }
}
function savePrefs(prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs))
  } catch {
    // private browsing
  }
}
function forgetPosition(id) {
  try {
    localStorage.removeItem(`${WINDOW_POS_PREFIX}${id}`)
  } catch {
    // private browsing
  }
}

export function WindowManagerProvider({ children }) {
  const [windows, setWindows] = useState([])
  const zCounter = useRef(BASE_Z)
  const { isAuthenticated } = useAuth()
  const [sameWindow, setSameWindow] = useState(() => loadPrefs().sameWindow ?? true)

  const toggleSameWindow = useCallback(() => {
    setSameWindow((prev) => {
      const next = !prev
      savePrefs({ ...loadPrefs(), sameWindow: next })
      return next
    })
  }, [])

  const getCenterPos = useCallback((index) => {
    const w = 520
    const h = 480
    const offset = index * CASCADE_OFFSET
    return {
      x: Math.max(20, Math.round((window.innerWidth - w) / 2) + offset),
      y: Math.max(20, Math.round((window.innerHeight - h) / 2) + offset),
      w,
      h,
    }
  }, [])

  const openWindow = useCallback(
    (type, entityId, data = {}) => {
      setWindows((prev) => {
        const id = `${type}:${entityId}`
        const existing = prev.find((w) => w.id === id)
        zCounter.current += 1
        if (existing) {
          return prev.map((w) => (w.id === id ? { ...w, zIndex: zCounter.current, data: { ...w.data, ...data } } : w))
        }
        if (sameWindow && prev.length > 0) {
          const idx = prev.findLastIndex((w) => w.type === type)
          if (idx >= 0) {
            const next = [...prev]
            next[idx] = { id, type, entityId, data, zIndex: zCounter.current, defaultPos: prev[idx].defaultPos, tileKey: Date.now() }
            return next
          }
        }
        const fresh = { id, type, entityId, data, zIndex: zCounter.current, defaultPos: getCenterPos(prev.length % 8) }
        let next = [...prev, fresh]
        if (next.length > MAX_WINDOWS) next = next.slice(next.length - MAX_WINDOWS)
        return next
      })
    },
    [sameWindow, getCenterPos],
  )

  const closeWindow = useCallback((id) => {
    forgetPosition(id)
    setWindows((prev) => prev.filter((w) => w.id !== id))
  }, [])

  const closeAll = useCallback(() => {
    setWindows((prev) => {
      prev.forEach((w) => forgetPosition(w.id))
      return []
    })
  }, [])

  useEffect(() => {
    if (!isAuthenticated) closeAll()
  }, [isAuthenticated, closeAll])

  const focusWindow = useCallback((id) => {
    zCounter.current += 1
    setWindows((prev) => prev.map((w) => (w.id === id ? { ...w, zIndex: zCounter.current } : w)))
  }, [])

  const tileWindows = useCallback(() => {
    setWindows((prev) => {
      if (prev.length === 0) return prev
      const gap = 12
      const sidebarW = 200
      const tileW = 500
      const tileH = 460
      const availW = window.innerWidth - sidebarW
      const cols = Math.max(1, Math.min(prev.length, Math.floor((availW - gap) / (tileW + gap))))
      const rows = Math.ceil(prev.length / cols)
      const offsetX = sidebarW + Math.max(gap, Math.round((availW - (cols * tileW + (cols - 1) * gap)) / 2))
      const offsetY = Math.max(gap, Math.round((window.innerHeight - (rows * tileH + (rows - 1) * gap)) / 2))
      return prev.map((w, i) => ({
        ...w,
        defaultPos: { x: offsetX + (i % cols) * (tileW + gap), y: offsetY + Math.floor(i / cols) * (tileH + gap), w: tileW, h: tileH },
        tileKey: Date.now() + i,
      }))
    })
  }, [])

  const stackWindows = useCallback(() => {
    setWindows((prev) => prev.map((w, i) => ({ ...w, defaultPos: getCenterPos(i), tileKey: Date.now() + i })))
  }, [getCenterPos])

  const updateWindowData = useCallback((id, data) => {
    setWindows((prev) => prev.map((w) => (w.id === id ? { ...w, data: { ...w.data, ...data } } : w)))
  }, [])

  return (
    <WindowManagerContext.Provider
      value={{
        windows,
        openWindow,
        closeWindow,
        closeAll,
        focusWindow,
        tileWindows,
        stackWindows,
        updateWindowData,
        windowCount: windows.length,
        sameWindow,
        toggleSameWindow,
      }}
    >
      {children}
    </WindowManagerContext.Provider>
  )
}

export function useWindowManager() {
  const ctx = useContext(WindowManagerContext)
  if (!ctx) throw new Error('useWindowManager must be used within WindowManagerProvider')
  return ctx
}
