// SPDX-License-Identifier: Apache-2.0
// Object keys of an exception by alert kind (docs/architecture.md, consistency exceptions):
// an example for the form and the shape a key must have.
import { EXCEPTABLE_KINDS, INCONSISTENCY_KINDS } from './kinds.js'

export const KEY_EXAMPLES = {
  ptr_mismatch: '192.0.2.90|mail.example.net.',
  lease_without_record: 'host1.example.lan.',
  record_without_lease: 'www.example.lan./A',
  reservation_mismatch: 'hw-address=00:11:22:33:44:55|192.0.2.50',
  duplicate_ip: '192.0.2.50',
}
// Health and audit checks: the alert subject, on every node, or <node id>|<subject> for one node.
const HEALTH_EXAMPLE = 'disk:/var/lib/pelagos'

const SHAPES = {
  ptr_mismatch: /^[0-9a-fA-F:.]+\|\S+$/,
  record_without_lease: /^\S+\/(A|AAAA)$/,
  reservation_mismatch: /^\S+\|[0-9a-fA-F:.]+$/,
  duplicate_ip: /^[0-9a-fA-F:.]+$/,
  lease_without_record: /^\S+$/,
}

export const exceptionKinds = () => [...INCONSISTENCY_KINDS, ...EXCEPTABLE_KINDS]

export function keyExample(kind) {
  return KEY_EXAMPLES[kind] || HEALTH_EXAMPLE
}

// 'required' | 'format' | null for a key typed by hand.
export function keyProblem(kind, key) {
  const value = String(key || '').trim()
  if (!value) return 'required'
  const shape = SHAPES[kind]
  if (shape) return shape.test(value) ? null : 'format'
  return /\s/.test(value) ? 'format' : null
}
