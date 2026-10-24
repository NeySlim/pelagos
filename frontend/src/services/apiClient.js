// SPDX-License-Identifier: Apache-2.0
// HTTP client for /api/v1: session cookie, X-CSRF-Token on unsafe methods, RFC 7807
// problem documents turned into ApiError. A 401 `unauthenticated` (lost session) fires
// `pelagos:unauthenticated` so AuthContext can drop the session without a hard reload.

import { renderMessage } from '../i18n/message'

export const API_BASE_URL = '/api/v1'
const CSRF_TOKEN_KEY = 'pelagos_csrf_token'
const UNSAFE_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']

export class ApiError extends Error {
  constructor(message, { status = 0, code = 'network_error', problem = null, errors = [] } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.problem = problem
    this.errors = errors
  }
}

function problemToError(status, data) {
  if (data && typeof data === 'object') {
    const code = data.code || (status === 401 ? 'unauthenticated' : status === 403 ? 'forbidden' : 'error')
    const message = data.detail || data.title || data.message || `HTTP ${status}`
    return new ApiError(message, { status, code, problem: data, errors: data.errors || [] })
  }
  const text = typeof data === 'string' && data ? data.slice(0, 200) : `HTTP ${status}`
  return new ApiError(text, { status, code: `http_${status}` })
}

let memoryCsrf = null

class APIClient {
  constructor() {
    this.baseURL = API_BASE_URL
  }

  getCsrfToken() {
    if (memoryCsrf) return memoryCsrf
    try {
      return sessionStorage.getItem(CSRF_TOKEN_KEY)
    } catch {
      return null
    }
  }

  setCsrfToken(token) {
    memoryCsrf = token || null
    try {
      if (token) sessionStorage.setItem(CSRF_TOKEN_KEY, token)
      else sessionStorage.removeItem(CSRF_TOKEN_KEY)
    } catch {
      // private browsing: the in-memory copy is enough for this tab
    }
  }

  clearCsrfToken() {
    this.setCsrfToken(null)
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`
    const method = (options.method || 'GET').toUpperCase()
    const headers = { Accept: 'application/json', ...options.headers }
    if (UNSAFE_METHODS.includes(method)) {
      const csrf = this.getCsrfToken()
      if (csrf) headers['X-CSRF-Token'] = csrf
    }
    const config = { method, headers, credentials: 'same-origin', signal: options.signal }
    if (options.body !== undefined && options.body !== null) {
      if (options.body instanceof FormData) {
        config.body = options.body
      } else {
        headers['Content-Type'] = 'application/json'
        config.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body)
      }
    }

    let response
    try {
      response = await fetch(url, config)
    } catch (err) {
      if (err?.name === 'AbortError') throw err
      throw new ApiError('Network error', { status: 0, code: 'network_error' })
    }

    const contentType = response.headers.get('content-type') || ''
    let data
    if (response.status === 204) {
      data = null
    } else if (/application\/(problem\+)?json/.test(contentType)) {
      data = await response.json()
    } else if (options.responseType === 'blob') {
      data = await response.blob()
    } else {
      data = await response.text()
    }

    if (!response.ok) {
      const error = problemToError(response.status, data)
      const isAuthEndpoint = endpoint.startsWith('/auth/login') || endpoint.startsWith('/auth/session')
      if (response.status === 401 && error.code === 'unauthenticated' && !isAuthEndpoint) {
        window.dispatchEvent(new CustomEvent('pelagos:unauthenticated', { detail: error }))
      }
      throw error
    }
    return data
  }

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' })
  }

  post(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'POST', body })
  }

  put(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'PUT', body })
  }

  patch(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'PATCH', body })
  }

  delete(endpoint, body, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE', body })
  }
}

export const apiClient = new APIClient()

// Query string from an object; null, undefined and '' are skipped, arrays repeat the key.
export function buildQueryString(params) {
  if (!params) return ''
  const qs = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    if (Array.isArray(value)) {
      value.forEach((v) => {
        if (v !== undefined && v !== null && v !== '') qs.append(key, String(v))
      })
    } else if (typeof value === 'boolean') {
      qs.append(key, value ? 'true' : 'false')
    } else {
      qs.append(key, String(value))
    }
  })
  const str = qs.toString()
  return str ? `?${str}` : ''
}

// The problem's detail in the UI language when the backend sent a message key for it
// (detail_message), else the English detail.
function problemText(err) {
  const keyed = err.problem?.detail_message
  return keyed ? renderMessage(keyed, err.message) : err.message
}

// Human message for an error coming out of apiClient (or anything else).
export function errorMessage(err, fallback = 'Request failed') {
  if (!err) return fallback
  if (err instanceof ApiError) {
    const base = problemText(err)
    if (err.errors?.length) {
      const first = err.errors[0]
      return first.field ? `${base}: ${first.field} ${first.message}` : `${base}: ${first.message}`
    }
    return base || fallback
  }
  return err.message || String(err) || fallback
}
