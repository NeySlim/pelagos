// SPDX-License-Identifier: Apache-2.0
// Pelagos mark: two swells and a beacon, colored by the --logo-gradient-* tokens.
import { useId } from 'react'
import { cn } from '../lib/utils'

const sizes = { xs: 20, sm: 26, md: 32, lg: 48, xl: 64 }

function LogoIcon({ size = 32, className }) {
  const uid = useId()
  const g1 = `pelagos-g1-${uid}`
  const g2 = `pelagos-g2-${uid}`
  return (
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" width={size} height={size} className={className} aria-hidden="true">
      <defs>
        <linearGradient id={g1} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="var(--logo-gradient-start)" />
          <stop offset="50%" stopColor="var(--logo-gradient-mid)" />
          <stop offset="100%" stopColor="var(--logo-gradient-end)" />
        </linearGradient>
        <linearGradient id={g2} x1="100%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="var(--logo-gradient-accent)" />
          <stop offset="100%" stopColor="var(--logo-gradient-start)" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="44" height="44" rx="11" fill={`url(#${g1})`} opacity="0.12" />
      <path d="M7 31c4-6 8-6 12 0s8 6 12 0 8-6 12 0" stroke={`url(#${g1})`} strokeWidth="3.5" strokeLinecap="round" />
      <path d="M7 21c4-6 8-6 12 0s8 6 12 0 8-6 12 0" stroke={`url(#${g2})`} strokeWidth="3" strokeLinecap="round" opacity="0.9" />
      <circle cx="24" cy="11" r="3" fill={`url(#${g2})`} />
    </svg>
  )
}

export function Logo({ variant = 'horizontal', withText = true, size = 'md', className }) {
  const iconPx = sizes[size] || sizes.md
  if (!withText || variant === 'icon') {
    return (
      <div className={className}>
        <LogoIcon size={iconPx} />
      </div>
    )
  }
  const vertical = variant === 'vertical'
  const fontSize = variant === 'compact' ? '18px' : size === 'lg' ? '32px' : '24px'
  return (
    <div className={cn('flex items-center', vertical && 'flex-col', className)} style={{ gap: variant === 'compact' ? '8px' : '12px' }}>
      <LogoIcon size={iconPx} />
      <div className={cn('flex flex-col', vertical && 'items-center')}>
        <div className="font-black tracking-tight leading-none logo-text-gradient" style={{ fontSize, letterSpacing: '-1px' }}>
          Pelagos
        </div>
        {variant !== 'compact' && (
          <div className="font-semibold uppercase" style={{ fontSize: '9px', letterSpacing: '2px', color: 'var(--text-tertiary)', marginTop: '2px' }}>
            DNS and DHCP
          </div>
        )}
      </div>
    </div>
  )
}
