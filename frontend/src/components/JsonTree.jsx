// SPDX-License-Identifier: Apache-2.0
// Collapsible JSON viewer for Kea configuration, user-context and raw payloads.
// Values coming from the engines are untrusted: everything renders as text.
import { useState } from 'react'
import { CaretRight, CaretDown } from '@phosphor-icons/react'
import { cn } from '../lib/utils'

function typeOf(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

function Scalar({ value }) {
  const type = typeOf(value)
  const cls = {
    string: 'text-status-success',
    number: 'text-accent-pro',
    boolean: 'text-accent-primary',
    null: 'text-text-tertiary italic',
    undefined: 'text-text-tertiary italic',
  }[type]
  const text = type === 'string' ? JSON.stringify(value) : String(value)
  return <span className={cn('font-mono text-xs break-all', cls)}>{text}</span>
}

function Node({ name, value, path, depth, expandedDepth, selectedPath, onSelect }) {
  const type = typeOf(value)
  const isContainer = type === 'object' || type === 'array'
  const [open, setOpen] = useState(depth < expandedDepth)
  const entries = isContainer ? (type === 'array' ? value.map((v, i) => [String(i), v]) : Object.entries(value)) : []
  const selected = selectedPath === path
  const label = name === undefined ? null : type === 'array' || /^\d+$/.test(name) ? name : name

  return (
    <div className="leading-5" data-testid="json-node">
      <div
        className={cn(
          'flex items-start gap-1 rounded px-1 -mx-1 cursor-default',
          onSelect && 'cursor-pointer hover:bg-bg-tertiary',
          selected && 'bg-accent-primary-op15',
        )}
        style={{ paddingLeft: `${depth * 14}px` }}
        onClick={() => onSelect?.(path, value)}
      >
        {isContainer ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              setOpen((o) => !o)
            }}
            className="w-4 h-5 flex items-center justify-center text-text-tertiary hover:text-text-primary shrink-0"
            aria-label={open ? 'collapse' : 'expand'}
          >
            {open ? <CaretDown size={10} weight="bold" /> : <CaretRight size={10} weight="bold" />}
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}
        {label !== null && <span className="font-mono text-xs text-text-secondary shrink-0">{label}:</span>}
        {isContainer ? (
          <span className="font-mono text-xs text-text-tertiary">
            {type === 'array' ? `[${entries.length}]` : `{${entries.length}}`}
          </span>
        ) : (
          <Scalar value={value} />
        )}
      </div>
      {isContainer && open && (
        <div>
          {entries.map(([k, v]) => (
            <Node
              key={k}
              name={k}
              value={v}
              path={path ? `${path}.${k}` : k}
              depth={depth + 1}
              expandedDepth={expandedDepth}
              selectedPath={selectedPath}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export function JsonTree({ data, expandedDepth = 2, selectedPath, onSelect, className }) {
  return (
    <div className={cn('text-xs font-mono select-text', className)} data-testid="json-tree">
      <Node value={data} path="" depth={0} expandedDepth={expandedDepth} selectedPath={selectedPath} onSelect={onSelect} />
    </div>
  )
}

export default JsonTree
