// SPDX-License-Identifier: Apache-2.0
// Sealed audit segments in the mock (architecture section 11 "Sealed segments", section 17 Audit):
// GET /audit/segments and POST /audit/segments/{name}/verify with the backend's shapes.

const SEGMENT_RE = /^audit-(\d{4})(?:-(\d+))?\.jsonl$/

export function mockSegments(state) {
  const node = state.nodeIds?.ns1 || 'node-1'
  return [
    {
      name: 'audit-2025.jsonl',
      year: 2025,
      n: 1,
      bytes: 482113,
      sealed: true,
      seal: {
        format: 1, segment: 'audit-2025.jsonl', year: 2025, node_id: node,
        sealed_at: '2026-01-01T00:00:41Z', version: '0.4.0', algorithm: 'sha256-chain',
        bytes: 482113, lines: 1203, entries: 1203,
        first_ts: '2025-01-01T00:02:11Z', last_ts: '2026-01-01T00:00:12Z',
        first_id: '01JGZ0000000000000000000A1', last_id: '01JH00000000000000000000Z9',
        chain: 'a'.repeat(64),
      },
    },
  ]
}

export function auditSegmentsHandlers(state, { notFound }) {
  return {
    'GET /audit/segments': () => ({
      segments: mockSegments(state),
      live: { name: 'audit.jsonl', bytes: 81234, entries: state.audit.length, first_ts: state.audit[0]?.ts || null },
      retention_years: state.settings?.retention?.audit_sealed_years ?? 0,
    }),
    'POST /audit/segments/{name}/verify': ({ params }) => {
      const segment = SEGMENT_RE.test(params.name) && mockSegments(state).find((s) => s.name === params.name)
      if (!segment) throw notFound(`audit segment ${params.name}`)
      return {
        name: segment.name, ok: true, reason: null, note: null,
        lines: segment.seal.lines, entries: segment.seal.entries, peers_checked: 1,
        checked_at: new Date().toISOString(),
      }
    },
  }
}
