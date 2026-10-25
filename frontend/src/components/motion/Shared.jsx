// SPDX-License-Identifier: Apache-2.0
// Shared elements: a node that exists before and after a navigation (a zone name, the
// zones panel) takes a view-transition-name only while a transition to or from `to` runs,
// and only at full motion, so it travels on the spring and no name is ever held twice.
import { createElement } from 'react'
import { useSharedName } from '../../hooks/useSharedName'

export function SharedElement({ name, to, as = 'span', style, children, ...props }) {
  const shared = useSharedName(name, to)
  return createElement(as, { ...props, style: shared ? { ...style, ...shared } : style }, children)
}
