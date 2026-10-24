// SPDX-License-Identifier: Apache-2.0
// User preferences: localStorage first, then best effort PUT /api/v1/account/preferences
// when a session exists. 501 (not built yet) and network errors are ignored.

import { apiClient } from '../services/apiClient'

const STORAGE_KEY = 'pelagos-preferences'
const listeners = new Set()
let authenticated = false

function read() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') || {}
  } catch {
    return {}
  }
}

function write(prefs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    // Private browsing or quota: the in-memory state is still applied.
  }
}

export function getPreferences() {
  return read()
}

export function setAuthenticated(value) {
  authenticated = Boolean(value)
}

export function subscribePreferences(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

// Called by AuthContext with the preferences the server returned for this user.
export function applyServerPreferences(prefs) {
  if (!prefs || typeof prefs !== 'object') return
  const merged = { ...read(), ...prefs }
  write(merged)
  listeners.forEach((fn) => fn(merged))
}

export function persistPreference(key, value) {
  const merged = { ...read(), [key]: value }
  write(merged)
  listeners.forEach((fn) => fn(merged))
  if (!authenticated) return
  apiClient.put('/account/preferences', { [key]: value }).catch(() => {})
}
