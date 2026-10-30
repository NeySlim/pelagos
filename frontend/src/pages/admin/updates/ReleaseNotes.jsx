// SPDX-License-Identifier: Apache-2.0
// NOTES.md of a release, rendered as plain React text (headings, lists, code): never as HTML.
import { parseNotes } from './updatesLib'

export function ReleaseNotes({ text, testId = 'updates-notes' }) {
  const blocks = parseNotes(text)
  if (!blocks.length) return null
  return (
    <div className="space-y-1.5 text-xs text-text-secondary" data-testid={testId}>
      {blocks.map((b, i) => {
        if (b.type === 'h') return <p key={i} className={b.level <= 2 ? 'text-sm font-semibold text-text-primary' : 'text-xs font-semibold text-text-primary'}>{b.text}</p>
        if (b.type === 'li') return <p key={i} className="pl-3 relative before:content-['-'] before:absolute before:left-0">{b.text}</p>
        if (b.type === 'code') return <pre key={i} className="font-mono text-2xs bg-bg-tertiary rounded-md p-2 overflow-x-auto whitespace-pre">{b.text}</pre>
        return <p key={i}>{b.text}</p>
      })}
    </div>
  )
}

export default ReleaseNotes
