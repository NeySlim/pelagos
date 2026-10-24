// SPDX-License-Identifier: Apache-2.0
// Password policy of section 16 checked before the request: 12 characters and
// three character classes. The server stays authoritative.
export function passwordProblem(password) {
  const value = String(password || '')
  if (value.length < 12) return 'passwordShort'
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length
  return classes < 3 ? 'passwordClasses' : null
}
