// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 observation (architecture section 27): the watched prefix list.

export const splitList = (text) => String(text || '').split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

// 'format' | 'scope' | null for one watched prefix typed by hand (ULA is allowed, it is opt-in).
export function prefixProblem(value) {
  const m = String(value).trim().match(/^([0-9a-f:]+)\/(\d{1,3})$/i)
  if (!m || !m[1].includes(':') || (m[1].match(/::/g) || []).length > 1) return 'format'
  const len = Number(m[2])
  if (len < 1 || len > 128) return 'format'
  const head = m[1].toLowerCase()
  if (/^fe[89ab]/.test(head) || head.startsWith('ff')) return 'scope'
  return null
}
