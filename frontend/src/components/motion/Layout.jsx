// SPDX-License-Identifier: Apache-2.0
// Layout-level motion and chrome: staggered panel entry, page transition, stat chips,
// round icon buttons and the atmospheric Mission backdrop. Entry animations use
// opacity and transform with a backwards fill, so nothing stays transformed afterwards.
import { Children, cloneElement, forwardRef, isValidElement, useMemo } from 'react'
import { cn } from '../../lib/utils'

// Each direct child enters after the previous one (index exposed as --fx-i).
export function Stagger({ children, as: Tag = 'div', step = 45, className, ...props }) {
  let i = 0
  return (
    <Tag className={cn('fx-stagger', className)} style={{ '--fx-step': `${step}ms` }} {...props}>
      {Children.map(children, (child) => {
        if (!isValidElement(child)) return child
        const index = i
        i += 1
        return cloneElement(child, { style: { ...child.props.style, '--fx-i': index } })
      })}
    </Tag>
  )
}

// Remounts on `routeKey` so each page fades in; keeps the flex column of <main>.
export function PageTransition({ routeKey, children, className }) {
  return (
    <div key={routeKey} className={cn('fx-page flex-1 flex flex-col min-h-0 min-w-0', className)} data-testid="page-transition">
      {children}
    </div>
  )
}

// Tiny uppercase label above a prominent value, with an optional icon.
export function StatChip({ icon: Icon, label, value, tone, className, ...props }) {
  return (
    <div className={cn('ui-stat-chip', tone && `fx-tone-${tone}`, className)} {...props}>
      {Icon && <Icon size={16} className="ui-stat-chip-icon shrink-0" />}
      <div className="min-w-0">
        <div className="ui-stat-chip-label">{label}</div>
        <div className="ui-stat-chip-value tabular-nums">{value}</div>
      </div>
    </div>
  )
}

export const IconButton = forwardRef(function IconButton({ icon: Icon, label, size = 'md', active = false, className, type = 'button', children, ...props }, ref) {
  const px = { sm: 14, md: 18, lg: 20 }[size] || 18
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      aria-pressed={active || undefined}
      className={cn('ui-icon-button', `ui-icon-button-${size}`, active && 'is-active', className)}
      {...props}
    >
      {Icon ? <Icon size={px} /> : children}
    </button>
  )
})

// Deterministic contour lines: distorted rings around two centers, like a depth chart.
function contourPaths() {
  const paths = []
  const centers = [
    [0.28, 0.72, 11, 0.9],
    [0.78, 0.3, 8, 1.7],
  ]
  for (const [cx, cy, count, phase] of centers) {
    for (let k = 1; k <= count; k += 1) {
      const r = k * 0.055
      let d = ''
      for (let s = 0; s <= 96; s += 1) {
        const a = (s / 96) * Math.PI * 2
        const wobble = 1 + 0.12 * Math.sin(3 * a + phase + k * 0.4) + 0.06 * Math.sin(7 * a - k * 0.3)
        const x = (cx + Math.cos(a) * r * wobble * 1.25) * 1000
        const y = (cy + Math.sin(a) * r * wobble) * 1000
        d += `${s ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`
      }
      paths.push(d + 'Z')
    }
  }
  return paths
}

// Full-bleed generated scene behind the app: gradient, depth grid, contours, vignette.
export function AppBackdrop({ className }) {
  const paths = useMemo(contourPaths, [])
  return (
    <div className={cn('fx-backdrop', className)} aria-hidden="true" data-testid="app-backdrop">
      <div className="fx-backdrop-grid" />
      <svg className="fx-backdrop-contours" viewBox="0 0 1000 1000" preserveAspectRatio="xMidYMid slice">
        {paths.map((d, i) => (
          <path key={i} d={d} />
        ))}
      </svg>
      <div className="fx-backdrop-vignette" />
    </div>
  )
}
