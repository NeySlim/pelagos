// SPDX-License-Identifier: Apache-2.0
// First label of a node name; an address stays whole.
export function shortNodeName(name) {
  if (!name) return name
  return /^[0-9.:[\]]+$/.test(name) ? name : name.split('.')[0]
}
