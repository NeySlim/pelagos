// SPDX-License-Identifier: Apache-2.0
// Procedures read top to bottom. Checklist: each check goes hollow, running arc, then a
// tick that draws itself, while a side rail fills check by check. StepRail: a 2 px rail
// fills step by step (linear: it represents time), each step carries node chips whose
// underline fills over the node's real duration; `reverse` walks it back in amber.
// States are always written out for screen readers; the marks are decorative.
import { useTranslation } from 'react-i18next'
import { cn } from '../../lib/utils'
import { RollingNumber } from './RollingNumber'
import { STEP_STATES, progressOf } from './primitives'

const normalize = (state) => (STEP_STATES.includes(state) ? state : 'pending')

export function CheckMark({ state = 'pending', className }) {
  const s = normalize(state)
  return (
    <span className={cn('fx-ck', `is-${s}`, className)} aria-hidden="true" data-state={s}>
      {(s === 'done' || s === 'failed') && (
        <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
          {s === 'done' ? <path pathLength="1" d="M2.2 5.3l1.9 1.9 3.8-4.2" /> : <path pathLength="1" d="M3 3l4 4M7 3l-4 4" />}
        </svg>
      )}
    </span>
  )
}

const formatMs = (ms) => (ms === undefined || ms === null ? '' : `${Math.round(ms)} ms`)

export function Checklist({ items = [], className, showCount = true, testId = 'checklist' }) {
  const { t } = useTranslation()
  const done = items.filter((i) => i.state === 'done').length
  return (
    <div className={className} data-testid={testId}>
      {showCount && (
        <div className="fx-checklist-count" data-testid={`${testId}-count`}>
          <RollingNumber value={`${done}/${items.length}`} delta={false} />
        </div>
      )}
      <div className="fx-checklist">
        <span className="fx-checklist-rail" aria-hidden="true">
          <i style={{ transform: `scaleY(${progressOf(items).toFixed(3)})` }} />
        </span>
        <ul className="flex flex-col">
          {items.map((item) => {
            const s = normalize(item.state)
            return (
              <li key={item.id ?? item.label} className={cn('fx-check', `is-${s}`)} data-state={s}>
                <CheckMark state={s} />
                <span className="min-w-0 truncate">{item.label}</span>
                {item.detail && <span className="fx-check-detail">{item.detail}</span>}
                <span className="sr-only">{t(`common:motion.states.${s}`)}</span>
                <span className="fx-check-ms">{formatMs(item.ms)}</span>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}

export function StepRail({ steps = [], reverse = false, className, testId = 'step-rail' }) {
  const { t } = useTranslation()
  // Walking back, the rail holds what is not reverted yet.
  const p = reverse ? 1 - progressOf(steps.map((s) => ({ state: s.state === 'reverted' ? 'done' : 'pending' }))) : progressOf(steps)
  return (
    <div className={cn('fx-rail', reverse && 'is-reverse', className)} data-testid={testId}>
      <span className="fx-rail-track" aria-hidden="true">
        <span className="fx-rail-fill" style={{ transform: `scaleY(${p.toFixed(3)})` }} />
      </span>
      <ol className="flex flex-col">
        {steps.map((step) => {
          const s = normalize(step.state)
          return (
            <li key={step.id ?? step.label} className={cn('fx-step', `is-${s}`)} data-state={s} data-testid={`${testId}-step`}>
              <CheckMark state={s} />
              <span className="fx-step-label">{step.label}</span>
              <span className="sr-only">{t(`common:motion.states.${s}`)}</span>
              {step.nodes?.length > 0 && (
                <span className="fx-step-nodes">
                  {step.nodes.map((node) => {
                    const ns = normalize(node.state)
                    return (
                      <span
                        key={node.name}
                        className={cn('fx-node-chip', `is-${ns}`)}
                        style={node.durationMs ? { '--fx-dn': `${Math.round(node.durationMs)}ms` } : undefined}
                        data-state={ns}
                      >
                        {node.name}
                      </span>
                    )
                  })}
                </span>
              )}
              <span className="fx-step-ms">{formatMs(step.ms)}</span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
