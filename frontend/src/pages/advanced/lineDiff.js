// SPDX-License-Identifier: Apache-2.0
// Local unified diff for the editors' pending changes, shown before the server
// builds the plan (whose own diff is authoritative). LCS on lines, 3 lines of
// context per hunk; empty string when both texts are equal.

function lcsTable(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1))
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  return dp
}

// Edit script: [{ kind: ' ' | '-' | '+', text, a, b }] with 0-based line numbers.
export function diffLines(before, after) {
  const a = before === '' ? [] : before.split('\n')
  const b = after === '' ? [] : after.split('\n')
  const dp = lcsTable(a, b)
  const ops = []
  let i = 0
  let j = 0
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      ops.push({ kind: ' ', text: a[i], a: i, b: j })
      i += 1
      j += 1
    } else if (j < b.length && (i >= a.length || dp[i][j + 1] >= dp[i + 1][j])) {
      ops.push({ kind: '+', text: b[j], a: i, b: j })
      j += 1
    } else {
      ops.push({ kind: '-', text: a[i], a: i, b: j })
      i += 1
    }
  }
  return ops
}

export function unifiedDiff(before, after, label = 'config', context = 3) {
  const ops = diffLines(before ?? '', after ?? '')
  const changed = ops.map((op, idx) => (op.kind !== ' ' ? idx : -1)).filter((idx) => idx >= 0)
  if (!changed.length) return ''
  // Group changed ops into hunks whose context windows touch.
  const hunks = []
  for (const idx of changed) {
    const last = hunks[hunks.length - 1]
    if (last && idx - last.end <= context * 2) last.end = idx
    else hunks.push({ start: idx, end: idx })
  }
  const out = [`--- a/${label}`, `+++ b/${label}`]
  for (const h of hunks) {
    const from = Math.max(0, h.start - context)
    const to = Math.min(ops.length - 1, h.end + context)
    const slice = ops.slice(from, to + 1)
    const aCount = slice.filter((o) => o.kind !== '+').length
    const bCount = slice.filter((o) => o.kind !== '-').length
    const aStart = aCount ? slice.find((o) => o.kind !== '+').a + 1 : slice[0].a
    const bStart = bCount ? slice.find((o) => o.kind !== '-').b + 1 : slice[0].b
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`)
    for (const o of slice) out.push(`${o.kind}${o.text}`)
  }
  return `${out.join('\n')}\n`
}

export const jsonText = (value) => (value === undefined ? '' : JSON.stringify(value, null, 2))
