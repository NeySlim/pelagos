// SPDX-License-Identifier: Apache-2.0
// Local unified diff for the editors' pending changes, shown before the server
// builds the plan (whose own diff is authoritative). LCS on lines, 3 lines of
// context per hunk; empty string when both texts are equal.

// Above this many cells, the changed window is shown as removed then added.
export const LCS_MAX_CELLS = 2000 * 2000

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
// The common prefix and suffix are matched directly; LCS runs on the middle only.
export function diffLines(before, after) {
  const a = before === '' ? [] : before.split('\n')
  const b = after === '' ? [] : after.split('\n')
  let start = 0
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1
  let endA = a.length
  let endB = b.length
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA -= 1
    endB -= 1
  }
  const ops = []
  for (let k = 0; k < start; k += 1) ops.push({ kind: ' ', text: a[k], a: k, b: k })
  const midA = a.slice(start, endA)
  const midB = b.slice(start, endB)
  if ((midA.length + 1) * (midB.length + 1) > LCS_MAX_CELLS) {
    midA.forEach((text, k) => ops.push({ kind: '-', text, a: start + k, b: start }))
    midB.forEach((text, k) => ops.push({ kind: '+', text, a: endA, b: start + k }))
  } else {
    const dp = lcsTable(midA, midB)
    let i = 0
    let j = 0
    while (i < midA.length || j < midB.length) {
      if (i < midA.length && j < midB.length && midA[i] === midB[j]) {
        ops.push({ kind: ' ', text: midA[i], a: start + i, b: start + j })
        i += 1
        j += 1
      } else if (i < midA.length && (j >= midB.length || dp[i + 1][j] >= dp[i][j + 1])) {
        ops.push({ kind: '-', text: midA[i], a: start + i, b: start + j })
        i += 1
      } else {
        ops.push({ kind: '+', text: midB[j], a: start + i, b: start + j })
        j += 1
      }
    }
  }
  for (let k = 0; k < a.length - endA; k += 1) ops.push({ kind: ' ', text: a[endA + k], a: endA + k, b: endB + k })
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
