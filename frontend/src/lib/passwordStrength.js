// SPDX-License-Identifier: Apache-2.0
// Local password strength estimate for the Input meter. The server enforces the
// real policy (12 chars, three character classes); this only paints a hint.

const LEVELS = ['weak', 'fair', 'good', 'strong']

export function localPasswordStrength(password) {
  if (!password) return { score: 0, level: 'weak' }
  let score = 0
  if (password.length >= 12) score += 1
  if (password.length >= 16) score += 1
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length
  if (classes >= 3) score += 1
  if (classes === 4 && password.length >= 14) score += 1
  score = Math.min(score, 3)
  return { score, level: LEVELS[score] }
}

// Kept async so Input.jsx is unchanged from UCM; no server round trip in Pelagos.
export function fetchPasswordStrength(password) {
  return Promise.resolve(localPasswordStrength(password))
}

export function barsForScore(score) {
  return Math.max(1, Math.min(4, (score ?? 0) + 1))
}
