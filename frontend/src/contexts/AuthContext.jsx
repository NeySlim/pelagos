// SPDX-License-Identifier: Apache-2.0
// Session state: GET /auth/session on mount, login/logout, CSRF token handed to
// apiClient, permissions, the node answering and GET /capabilities (modules and
// engines) used to gate navigation. A 401 from any call drops the session.
import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react'
import { clearLists } from '../lib/listCache'
import { api } from '../services/api'
import { apiClient } from '../services/apiClient'
import { resetLiveRates } from '../hooks/useLiveRates'
import { applyServerPreferences, getPreferences, setAuthenticated as setPrefsAuthenticated } from '../stores/preferencesStore'
import i18n from '../i18n'

const AuthContext = createContext(null)

function applyPreferences(prefs) {
  applyServerPreferences(prefs || {})
  const language = getPreferences().language
  if (language && language !== i18n.language) {
    try {
      i18n.changeLanguage(language)
    } catch {
      // the detector keeps the previous language
    }
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [permissions, setPermissions] = useState([])
  const [node, setNode] = useState(null)
  const [capabilities, setCapabilities] = useState(null)
  const [loading, setLoading] = useState(true)
  const [sessionChecked, setSessionChecked] = useState(false)

  const clearSession = useCallback(() => {
    setUser(null)
    setPermissions([])
    setCapabilities(null)
    apiClient.clearCsrfToken()
    setPrefsAuthenticated(false)
    resetLiveRates()
  }, [])

  const loadCapabilities = useCallback(async () => {
    try {
      const caps = await api.meta.capabilities()
      setCapabilities(caps)
      if (caps?.node) setNode(caps.node)
      return caps
    } catch {
      // Module-gated routes wait for capabilities: settle on "nothing optional".
      const fallback = { modules: { dhcpv6: false, advanced_editor: false }, engines: {}, failed: true }
      setCapabilities(fallback)
      return fallback
    }
  }, [])

  const adoptSession = useCallback(
    (data) => {
      setUser(data.user || null)
      setPermissions(data.permissions || [])
      if (data.csrf_token) apiClient.setCsrfToken(data.csrf_token)
      if (data.node) setNode(data.node)
      setPrefsAuthenticated(true)
      applyPreferences(data.user?.preferences)
      loadCapabilities()
    },
    [loadCapabilities],
  )

  const checkSession = useCallback(async () => {
    try {
      const data = await api.auth.session()
      if (!data || typeof data !== 'object' || !data.user) {
        clearSession()
        return false
      }
      adoptSession(data)
      return true
    } catch (error) {
      // An unreachable server says nothing about the session: keep the current state.
      if (error?.status === 401 || error?.status === 403) clearSession()
      return false
    } finally {
      setLoading(false)
      setSessionChecked(true)
    }
  }, [adoptSession, clearSession])

  useEffect(() => {
    checkSession()
  }, [checkSession])

  useEffect(() => {
    const onUnauthenticated = () => clearSession()
    window.addEventListener('pelagos:unauthenticated', onUnauthenticated)
    return () => window.removeEventListener('pelagos:unauthenticated', onUnauthenticated)
  }, [clearSession])

  // Throws ApiError; code 'totp_required' means the caller must ask for a code.
  const login = useCallback(
    async (username, password, totpCode) => {
      const data = await api.auth.login(username, password, totpCode)
      adoptSession(data)
      return data
    },
    [adoptSession],
  )

  const logout = useCallback(async () => {
    try {
      await api.auth.logout()
    } catch {
      // the local state is cleared regardless
    } finally {
      clearLists()
      clearSession()
    }
  }, [clearSession])

  const hasPermission = useCallback(
    (required) => {
      if (!required) return true
      if (!permissions.length) return false
      if (permissions.includes('*')) return true
      const list = Array.isArray(required) ? required : [required]
      return list.some((p) => permissions.includes(p))
    },
    [permissions],
  )

  const value = useMemo(
    () => ({
      user,
      permissions,
      node,
      capabilities,
      modules: capabilities?.modules || { dhcpv6: false, advanced_editor: false },
      engines: capabilities?.engines || {},
      isAuthenticated: Boolean(user),
      isAdmin: permissions.includes('*'),
      loading,
      sessionChecked,
      login,
      logout,
      checkSession,
      refreshCapabilities: loadCapabilities,
      hasPermission,
      updateUser: (patch) => setUser((prev) => (prev ? { ...prev, ...patch } : prev)),
    }),
    [user, permissions, node, capabilities, loading, sessionChecked, login, logout, checkSession, loadCapabilities, hasPermission],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used within AuthProvider')
  return context
}
