// SPDX-License-Identifier: Apache-2.0
// Decorative motion primitives. Every loop is a CSS transform or opacity animation
// marked fx-loop, which the motion level and a hidden page stop (styles/effects.css).
import { useMemo } from 'react'
import { cn } from '../../lib/utils'

const TONES = ['primary', 'pro', 'success', 'warning', 'danger', 'neutral']
const tone = (t) => (TONES.includes(t) ? t : 'neutral')

// Small colored dot next to a state word; `pulse` adds an expanding halo.
export function StatusDot({ tone: t = 'success', pulse = false, size = 6, className, label }) {
  return (
    <span
      className={cn('fx-dot', `fx-tone-${tone(t)}`, pulse && 'fx-dot-pulse', className)}
      style={{ '--fx-dot': `${size}px` }}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : 'true'}
      data-testid="status-dot"
    />
  )
}

// Ground halo under a waypoint: concentric ellipses that breathe outwards.
export function PulsingHalo({ tone: t = 'primary', size = 40, rings = 2, flat = true, className }) {
  return (
    <span
      className={cn('fx-halo', `fx-tone-${tone(t)}`, flat && 'fx-halo-flat', className)}
      style={{ '--fx-halo': `${size}px` }}
      aria-hidden="true"
    >
      <span className="fx-halo-core" />
      {Array.from({ length: rings }, (_, i) => (
        <span key={i} className="fx-halo-ring fx-loop" style={{ animationDelay: `${(i * 1.6) / rings}s` }} />
      ))}
    </span>
  )
}

// Dashed beam whose dashes flow along it. The dash strip moves by transform only.
export function FlowLine({ direction = 'horizontal', tone: t = 'primary', length = '100%', thickness = 2, reverse = false, className }) {
  const vertical = direction === 'vertical'
  return (
    <span
      className={cn('fx-flow', vertical ? 'fx-flow-v' : 'fx-flow-h', `fx-tone-${tone(t)}`, reverse && 'fx-flow-reverse', className)}
      style={vertical ? { height: length, width: thickness } : { width: length, height: thickness }}
      aria-hidden="true"
    >
      <span className="fx-flow-strip fx-loop" />
    </span>
  )
}

// Corner-bracket reticle drawn around its children.
export function Reticle({ children, tone: t = 'primary', size = 10, className, as: Tag = 'div', ...props }) {
  return (
    <Tag className={cn('fx-reticle', `fx-tone-${tone(t)}`, className)} style={{ '--fx-reticle': `${size}px` }} {...props}>
      <span className="fx-reticle-corners" aria-hidden="true" />
      {children}
    </Tag>
  )
}

function ticks(count, r, long, short) {
  const out = []
  for (let i = 0; i < count; i += 1) {
    const a = (i / count) * Math.PI * 2
    const len = i % 5 === 0 ? long : short
    const [c, s] = [Math.cos(a), Math.sin(a)]
    out.push(`M${(50 + c * r).toFixed(2)} ${(50 + s * r).toFixed(2)}L${(50 + c * (r - len)).toFixed(2)} ${(50 + s * (r - len)).toFixed(2)}`)
  }
  return out.join('')
}

// Perspective radar disc: rotating tick ring, sweep and range rings. `tilt` in degrees
// lays the disc on the ground; children render on top, centered.
export function RadarRing({ size = 280, tilt = 62, sweep = true, tone: t = 'primary', className, children }) {
  const tickPath = useMemo(() => ticks(72, 49, 4, 2), [])
  return (
    <div className={cn('fx-radar', `fx-tone-${tone(t)}`, className)} style={{ '--fx-radar': `${size}px`, '--fx-tilt': `${tilt}deg` }} data-testid="radar-ring">
      <div className="fx-radar-plane" aria-hidden="true">
        <div className="fx-radar-disc" />
        {sweep && <div className="fx-radar-sweep fx-loop" />}
        <svg className="fx-radar-rings" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="30" />
          <circle cx="50" cy="50" r="15" />
        </svg>
        <div className="fx-radar-ticks fx-loop">
          <svg viewBox="0 0 100 100">
            <path d={tickPath} />
          </svg>
        </div>
      </div>
      {children && <div className="fx-radar-content">{children}</div>}
    </div>
  )
}
