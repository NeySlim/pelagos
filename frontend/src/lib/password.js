// SPDX-License-Identifier: Apache-2.0
// Same rule as backend/pelagos/auth/passwords.py check_strength(): 12 characters
// and three of lowercase, uppercase, digits, symbols. The server stays authoritative.
export const PASSWORD_MIN = 12

export function passwordProblem(password) {
  const value = String(password || '')
  if (value.length < PASSWORD_MIN) return 'passwordShort'
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length
  return classes < 3 ? 'passwordClasses' : null
}
