// SPDX-License-Identifier: Apache-2.0
// Backend messages ({"key", "params"}, architecture section 19) rendered from the
// `messages` namespace. Keys are flat (dots are part of the key). A message whose key,
// or any nested key, is unknown here renders as the English text the backend sent.
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import i18n from './index'

export const MESSAGES_NS = 'messages'

export function isMessage(value) {
  return Boolean(value) && typeof value === 'object' && typeof value.key === 'string' && 'params' in value
}

const MISSING = Symbol('missing')

function renderValue(t, value) {
  if (isMessage(value)) return renderKey(t, value)
  if (value && typeof value === 'object' && Array.isArray(value.join)) {
    const parts = value.join.map((v) => renderValue(t, v))
    return parts.includes(MISSING) ? MISSING : parts.join(value.sep ?? ', ')
  }
  if (Array.isArray(value)) {
    const parts = value.map((v) => renderValue(t, v))
    return parts.includes(MISSING) ? MISSING : parts.join(', ')
  }
  return value === null || value === undefined ? '' : String(value)
}

function renderKey(t, message) {
  const opts = { ns: MESSAGES_NS, keySeparator: false, nsSeparator: false }
  if (!i18n.exists(message.key, opts)) return MISSING
  const replace = {}
  for (const [name, value] of Object.entries(message.params || {})) {
    const text = renderValue(t, value)
    if (text === MISSING) return MISSING
    replace[name] = text
  }
  // `replace` keeps parameter names out of i18next's own options; only a numeric `count`
  // goes through as well, so `<key>_one`/`<key>_other` resolve (the base key is the fallback).
  const count = message.params?.count
  const plural = typeof count === 'number' ? { count } : {}
  return t(message.key, { ...opts, ...plural, replace, interpolation: { escapeValue: false } })
}

// The text of `message` in the current language, or `fallback` (the backend's English).
export function renderMessage(message, fallback = '', t = i18n.t.bind(i18n)) {
  if (!isMessage(message)) return fallback ?? ''
  const text = renderKey(t, message)
  return text === MISSING ? fallback ?? '' : text
}

// Hook form: re-renders on language change.
export function useMessage() {
  const { t } = useTranslation(MESSAGES_NS)
  return useCallback((message, fallback) => renderMessage(message, fallback, t), [t])
}
