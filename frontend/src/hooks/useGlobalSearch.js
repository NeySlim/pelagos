// SPDX-License-Identifier: Apache-2.0
// Who may search, and the keys that open the search palette.
import { useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'

const SEARCH_PERMISSIONS = ['read:hosts', 'read:dns', 'read:dhcp']

export function useCanSearch() {
  const { hasPermission } = useAuth()
  return SEARCH_PERMISSIONS.some((p) => hasPermission(p))
}

// Mac: Cmd+K only (Ctrl+K deletes to the end of the line in a text field); elsewhere Ctrl+K.
export const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '')
export const searchShortcutLabel = () => (isMac() ? '\u2318K' : 'Ctrl K')

function typing(target) {
  if (!target || !target.tagName) return false
  return ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable
}

// Ctrl+K or Cmd+K anywhere; "/" only while nothing is being typed into.
export function useSearchShortcut(onOpen, enabled = true) {
  useEffect(() => {
    if (!enabled) return undefined
    const onKey = (e) => {
      if (e.defaultPrevented || e.altKey) return
      const k = e.key
      if ((isMac() ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey) && !e.shiftKey && (k === 'k' || k === 'K')) {
        e.preventDefault()
        onOpen()
      } else if (k === '/' && !e.ctrlKey && !e.metaKey && !typing(e.target)) {
        e.preventDefault()
        onOpen()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onOpen, enabled])
}
