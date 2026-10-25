// SPDX-License-Identifier: Apache-2.0
// Table rows that arrive and leave. A row unfolds through grid-template-rows (0fr to 1fr,
// the one sanctioned height animation), its content fades in 110 ms later, and it carries
// a short highlight; leaving is the reverse. flipRows glides reordered rows to their new
// place on the spring. Below full motion rows only fade; at off they change at once.
import { Children, cloneElement, isValidElement, useEffect, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { cn } from '../../lib/utils'

const LEAVE_MS = { full: 260, reduced: 160, off: 0 }

function wrapCells(children) {
  return Children.map(children, (cell) => {
    if (!isValidElement(cell)) return cell
    return cloneElement(cell, {}, (
      <div className="fx-cw">
        <div>
          <div className="fx-cw-pad">{cell.props.children}</div>
        </div>
      </div>
    ))
  })
}

function nextFrame(fn) {
  if (typeof window === 'undefined' || !window.requestAnimationFrame) {
    fn()
    return () => {}
  }
  let inner = 0
  const outer = window.requestAnimationFrame(() => {
    inner = window.requestAnimationFrame(fn)
  })
  return () => {
    window.cancelAnimationFrame(outer)
    window.cancelAnimationFrame(inner)
  }
}

// A <tr> that unfolds into place. `highlight` tints it once (--fx-row-hl, default DNS).
export function RowEnter({ children, className, highlight = true, ...props }) {
  const level = useMotionLevel()
  const [folded, setFolded] = useState(level === 'full')
  useEffect(() => {
    if (!folded) return undefined
    return nextFrame(() => setFolded(false))
  }, [folded])
  return (
    <tr className={cn('fx-row', folded && 'is-folded', highlight && level !== 'off' && 'is-highlight', className)} data-row-phase="enter" {...props}>
      {wrapCells(children)}
    </tr>
  )
}

// A <tr> on its way out: it folds (fades below full) and then calls onLeft once. `holdMs`
// keeps it in place first (an acknowledged alert is struck through before it folds).
export function RowLeave({ children, className, onLeft, holdMs = 0, style, ...props }) {
  const level = useMotionLevel()
  const [gone, setGone] = useState(false)
  const done = useRef(onLeft)
  useEffect(() => {
    done.current = onLeft
  })
  useEffect(() => {
    const cancel = nextFrame(() => setGone(true))
    const timer = setTimeout(() => done.current?.(), (LEAVE_MS[level] ?? 0) + (level === 'off' ? 0 : holdMs))
    return () => {
      cancel()
      clearTimeout(timer)
    }
  }, [level, holdMs])
  return (
    <tr
      className={cn('fx-row', gone && (level === 'full' ? 'is-folded' : 'is-faded'), className)}
      data-row-phase="leave"
      aria-hidden="true"
      style={holdMs ? { ...style, '--fx-leave-hold': `${holdMs}ms` } : style}
      {...props}
    >
      {wrapCells(children)}
    </tr>
  )
}
