// SPDX-License-Identifier: Apache-2.0
// Marks that belong to DNS, DHCP and HA events. Dora: four ticks landing 90 ms apart for a
// lease that just arrived. HeartbeatTrace: a QRS that traces itself on each heartbeat
// received, then rests at 35 %. UnsentQueue: lease updates waiting for the partner, one
// tick per update, that fill and drain. TransferBar and TransferSerial: a measured zone
// transfer (head, tail 300 ms behind) and the serial that rolls when it arrives.
// Everything here is decorative (aria-hidden) next to a value written as text.
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMotionLevel } from '../../contexts/MotionContext'
import { cn } from '../../lib/utils'
import { RollingNumber } from './RollingNumber'

export const DORA_STEP_MS = 90
export const DORA_LAND_MS = 320
export const TRANSFER_MS = 900
export const TRANSFER_TAIL_MS = 300
export const QUEUE_SLOTS = 24
export const QUEUE_DRAIN_MS = 70

// DISCOVER, OFFER, REQUEST, ACK. `nak` stops on a red last tick that stays. `transient`
// fades the mark away once it has landed (table rows), then calls onDone.
export function Dora({ play = true, nak = false, transient = false, onDone, className }) {
  const { t } = useTranslation()
  const level = useMotionLevel()
  const animate = play && level !== 'off'
  const [gone, setGone] = useState(false)
  const [finished, setFinished] = useState(false)
  const done = useRef(onDone)
  useEffect(() => {
    done.current = onDone
  })
  useEffect(() => {
    if (!transient) return undefined
    const hold = level === 'off' ? 1200 : 3 * DORA_STEP_MS + DORA_LAND_MS + 1200
    const fade = setTimeout(() => setGone(true), hold)
    const end = setTimeout(() => {
      setFinished(true)
      done.current?.()
    }, hold + (level === 'off' ? 0 : 200))
    return () => {
      clearTimeout(fade)
      clearTimeout(end)
    }
  }, [transient, level])
  if (finished) return null
  return (
    <span
      className={cn('fx-dora', animate && 'is-go', nak && 'is-nak', gone && 'is-gone', className)}
      data-testid="dora"
      data-state={nak ? 'nak' : 'ack'}
      title={t('motion.dora')}
      aria-hidden="true"
    >
      <i />
      <i />
      <i />
      <i />
      <span>D</span>
      <span>O</span>
      <span>R</span>
      <span>{nak ? 'N' : 'A'}</span>
    </span>
  )
}

// One QRS per heartbeat: `beat` changes when a new sample arrives. `lost` draws a red dashed
// baseline instead: nothing beats when the partner is gone, which is the signal.
export function HeartbeatTrace({ beat = 0, lost = false, className, testId = 'heartbeat' }) {
  const level = useMotionLevel()
  const seen = useRef(beat)
  const [gen, setGen] = useState(0)
  useEffect(() => {
    if (seen.current === beat) return
    seen.current = beat
    setGen((g) => g + 1)
  }, [beat])
  return (
    <span className={cn('fx-ecg', lost && 'is-lost', className)} data-testid={testId} data-beats={gen} aria-hidden="true">
      <svg viewBox="0 0 48 14" fill="none" preserveAspectRatio="none">
        {lost ? (
          <path d="M0 9.5H48" className="fx-ecg-flat" />
        ) : (
          <path
            key={gen}
            pathLength="1"
            d="M0 9.5H17L19 8 21 9.5 23 11 25.5 1.5 28 12.5 30 9.5H35L37 8 39 9.5H48"
            className={cn('fx-ecg-qrs', gen > 0 && level !== 'off' && 'is-beat')}
          />
        )}
      </svg>
    </span>
  )
}

// Lease updates waiting for the HA partner: one 1 x 6 px tick per update (up to
// QUEUE_SLOTS, then a "+"), new ones land, sent ones leave toward the partner 70 ms apart.
export function UnsentQueue({ count, className, testId = 'unsent-queue' }) {
  const level = useMotionLevel()
  const value = Number.isFinite(Number(count)) ? Math.max(0, Math.floor(Number(count))) : null
  const shown = value === null ? 0 : Math.min(value, QUEUE_SLOTS)
  const prev = useRef(shown)
  const [leaving, setLeaving] = useState(null) // { from, to, gen }
  const [landing, setLanding] = useState(0) // index from which slots just landed
  useEffect(() => {
    const before = prev.current
    prev.current = shown
    if (shown === before) return undefined
    if (level === 'off') {
      setLeaving(null)
      return undefined
    }
    if (shown < before) {
      setLeaving((l) => ({ from: shown, to: before, gen: (l?.gen || 0) + 1 }))
      const ms = (before - shown) * QUEUE_DRAIN_MS + 600
      const timer = setTimeout(() => setLeaving(null), ms)
      return () => clearTimeout(timer)
    }
    setLanding(before)
    return undefined
  }, [shown, level])
  const slots = []
  for (let i = 0; i < shown; i += 1) slots.push(<i key={`s${i}`} className={cn(i >= landing && level !== 'off' && 'is-in')} />)
  if (leaving) {
    // The oldest update leaves first: draining walks from the head of the queue.
    for (let i = leaving.from; i < leaving.to; i += 1) {
      slots.push(<i key={`l${leaving.gen}-${i}`} className="is-out" style={{ '--fx-k': i - leaving.from }} />)
    }
  }
  return (
    <span className={cn('fx-queue', className)} data-testid={testId} data-count={value ?? ''} data-draining={leaving ? 'true' : undefined}>
      <span className="fx-queue-slots" aria-hidden="true">
        {slots}
        {value !== null && value > QUEUE_SLOTS && <b>+</b>}
      </span>
      {value === null ? <span>-</span> : <RollingNumber value={value} delta={false} />}
    </span>
  )
}

// A measured transport along a 1 px track: the head leaves, the tail follows 300 ms later,
// both at constant speed. `run` restarts it (a counter); nothing travels below full motion.
export function TransferBar({ run = 0, durationMs = TRANSFER_MS, tone = 'dns', label, className }) {
  const level = useMotionLevel()
  const active = run > 0 && level === 'full'
  return (
    <span className={cn('fx-xfer', `fx-xfer-${tone}`, className)} aria-hidden="true" data-testid="transfer-bar" data-run={active ? run : undefined}>
      {active && <i key={run} style={{ '--fx-xfer': `${Math.max(TRANSFER_TAIL_MS * 2, durationMs)}ms` }} />}
      {active && label && <span key={`l${run}`}>{label}</span>}
    </span>
  )
}

// A serial that catches up through a zone transfer: at full motion the transfer bar runs
// first and the serial rolls when the head arrives; below full it changes at once.
export function TransferSerial({ value, transfer = true, tone = 'dns', label, className, testId }) {
  const level = useMotionLevel()
  const [shown, setShown] = useState(value)
  const [run, setRun] = useState(0)
  const [hl, setHl] = useState(0)
  const last = useRef(value)
  useEffect(() => {
    const before = last.current
    if (before === value) return undefined
    last.current = value
    const rising = Number(value) > Number(before)
    if (level !== 'full' || !transfer || !rising || before === null || before === undefined) {
      setShown(value)
      if (level !== 'off' && rising) setHl((h) => h + 1)
      return undefined
    }
    setRun((r) => r + 1)
    const arrive = setTimeout(() => {
      setShown(value)
      setHl((h) => h + 1)
    }, TRANSFER_MS - TRANSFER_TAIL_MS)
    return () => {
      clearTimeout(arrive)
      setShown(value)
    }
  }, [value, transfer, level])
  return (
    <span className={cn('fx-xserial', className)} data-testid={testId} data-value={shown ?? ''}>
      {/* Two identical keyframes alternate so each arrival restarts the highlight. */}
      <span className={cn(hl > 0 && (hl % 2 ? 'fx-hl-a' : 'fx-hl-b'))}>
        <RollingNumber value={shown ?? '-'} />
      </span>
      <TransferBar run={run} tone={tone} label={label} />
    </span>
  )
}
