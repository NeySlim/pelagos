// SPDX-License-Identifier: Apache-2.0
import { cn } from '../lib/utils'
import { StatusDot } from './motion/Decor'

export function Badge({ 
  children, 
  variant = 'default', 
  size = 'default', 
  dot = false, 
  pulse = false,  // Animated dot
  icon: Icon,     // Optional icon
  className, 
  ...props 
}) {
  // Theme-aware variants using CSS classes defined in index.css
  const variants = {
    default: 'bg-tertiary-op80 text-text-primary border-transparent',
    primary: 'status-primary-bg status-primary-text border-transparent',
    secondary: 'bg-tertiary-op60 text-text-secondary border-transparent',
    success: 'status-success-bg status-success-text border-transparent',
    warning: 'status-warning-bg status-warning-text border-transparent',
    danger: 'status-danger-bg status-danger-text border-transparent',
    info: 'status-primary-bg status-primary-text border-transparent',
    outline: 'bg-transparent text-text-primary border-border hover:bg-tertiary-op50',
    // Named color variants (still theme-aware through CSS)
    emerald: 'status-success-bg status-success-text border-transparent',
    red: 'status-danger-bg status-danger-text border-transparent',
    blue: 'status-primary-bg status-primary-text border-transparent',
    yellow: 'status-warning-bg status-warning-text border-transparent',
    purple: 'icon-bg-violet border-transparent',
    violet: 'icon-bg-violet border-transparent',
    amber: 'status-warning-bg status-warning-text border-transparent',
    orange: 'icon-bg-orange border-transparent',
    cyan: 'icon-bg-teal border-transparent',
    teal: 'icon-bg-teal border-transparent',
    gray: 'bg-tertiary-op60 text-text-secondary border-transparent',
  }
  
  // Badge variant to StatusDot tone; anything else is neutral.
  const dotTones = {
    primary: 'primary', info: 'primary', blue: 'primary', cyan: 'primary',
    success: 'success', emerald: 'success', teal: 'success',
    warning: 'warning', yellow: 'warning', amber: 'warning', orange: 'warning',
    danger: 'danger', red: 'danger',
    violet: 'pro', purple: 'pro',
  }
  
  // Sizes: sm is pill-shaped, others are rounded
  const sizes = {
    sm: 'px-2 py-px text-2xs gap-1 rounded-full',
    default: 'px-2.5 py-0.5 text-xs gap-1.5 rounded-md',
    lg: 'px-3 py-1 text-sm gap-2 rounded-md',
  }
  
  const iconSizes = {
    sm: 10,
    default: 12,
    lg: 14,
  }
  
  return (
    <span
      className={cn(
        'ui-badge inline-flex items-center font-semibold border badge-enhanced',
        `ui-badge-${variant}`,
        'transition-all duration-200 whitespace-nowrap',
        sizes[size],
        variants[variant],
        className
      )}
      {...props}
    >
      {dot && <StatusDot tone={dotTones[variant] || 'neutral'} pulse={pulse} className="ui-badge-dot" />}
      {Icon && <Icon size={iconSizes[size]} weight="bold" className="shrink-0" />}
      {children}
    </span>
  )
}

