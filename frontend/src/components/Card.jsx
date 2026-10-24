// SPDX-License-Identifier: Apache-2.0
import { cn } from '../lib/utils'
import { IconBadge } from './IconBadge'
import { titleCaseClass } from '../lib/displayCase'

export function Card({ 
  children, 
  className, 
  hover: _hover = true, 
  interactive = false, // clickable card with lift effect
  variant = 'default',  // default, elevated, bordered, soft
  accent,  // left border color: 'primary', 'success', 'warning', 'danger', 'info'
  ...props 
}) {
  const variants = {
    default: 'card-soft',
    elevated: cn(
      'bg-bg-secondary border border-border-op40 rounded-xl',
      'elevation-2',
    ),
    bordered: cn(
      'bg-secondary-op50 border-2 border-border rounded-xl',
    ),
    soft: 'card-soft',
  }
  
  const accentColors = {
    primary: 'border-l-accent-primary',
    success: 'border-l-accent-success',
    warning: 'border-l-accent-warning',
    danger: 'border-l-accent-danger',
    info: 'border-l-accent-primary',
    purple: 'border-l-accent-purple',
  }
  
  return (
    <div
      className={cn(
        interactive ? 'card-interactive' : variants[variant],
        accent && `border-l-4 ${accentColors[accent]}`,
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}

// Card sub-components for structured content
Card.Header = function CardHeader({ children, className, icon: Icon, iconColor = 'primary', title, subtitle, action }) {
  if (Icon || title) {
    return (
      <div className={cn('ui-card-header flex items-start justify-between gap-3 p-3 pb-2 border-b border-border-op30 section-header-gradient', className)}>
        <div className="flex items-center gap-3">
          {Icon && (
            <IconBadge icon={Icon} color={iconColor} size="sm" rounded="lg" />
          )}
          <div>
            {title && <h3 className={cn('ui-card-title text-sm font-semibold text-text-primary', titleCaseClass(title))}>{title}</h3>}
            {subtitle && <p className="text-xs text-text-secondary mt-0.5">{subtitle}</p>}
          </div>
        </div>
        {action}
      </div>
    )
  }
  return <div className={cn('p-3 pb-2 border-b border-border-op30', className)}>{children}</div>
}

Card.Body = function CardBody({ children, className }) {
  return <div className={cn('px-3 py-2.5', className)}>{children}</div>
}

Card.Footer = function CardFooter({ children, className }) {
  return (
    <div className={cn('px-3 py-2.5 border-t border-border-op50 bg-tertiary-op30 rounded-b-xl', className)}>
      {children}
    </div>
  )
}
