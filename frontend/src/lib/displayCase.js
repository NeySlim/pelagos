// SPDX-License-Identifier: Apache-2.0
// The Mission display face uppercases titles. A title carrying an identifier (DNS
// name, address, prefix, key) must keep its case, so it gets the literal class.
const IDENTIFIER = /[.:/@_]/

export function isLiteralTitle(title, literal) {
  if (literal !== undefined) return Boolean(literal)
  return typeof title === 'string' ? IDENTIFIER.test(title) : true
}

// Class added next to a display title: `ui-title-literal` turns the uppercase off.
export function titleCaseClass(title, literal) {
  return isLiteralTitle(title, literal) ? 'ui-title-literal' : 'ui-title-static'
}
