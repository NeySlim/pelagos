// SPDX-License-Identifier: Apache-2.0
/**
 * RichStatsBar - Dashboard-style stat cards for list pages
 * 
 * Creates visually rich statistics similar to Dashboard cards
 * with gradient icons and hover effects
 */
import { cn } from '../../lib/utils'
import { Stagger } from '../motion/Layout'
import { AnimatedValue } from '../motion/CountUp'

const variantClasses = {
  success: 'rich-stat-icon-success',
  warning: 'rich-stat-icon-warning',
  danger: 'rich-stat-icon-danger',
  primary: 'rich-stat-icon-primary',
  neutral: 'rich-stat-icon-neutral',
  default: 'rich-stat-icon-neutral',
  secondary: 'rich-stat-icon-neutral'
}

/**
 * @param {Array} stats - Array of { icon: Icon, label: string, value: number|string, variant: string }
 * @param {string} className - Additional classes
 */
export function RichStatsBar({ stats = [], className }) {
  if (!stats || stats.length === 0) return null

  return (
    <Stagger className={cn('rich-stats-bar', className)} data-testid="rich-stats-bar">
      {stats.map((stat, idx) => {
        const Icon = stat.icon
        const variantClass = variantClasses[stat.variant] || variantClasses.neutral
        
        return (
          <div key={idx} className="rich-stat-item">
            {Icon && (
              <div className={cn('rich-stat-icon', variantClass)}>
                <Icon size={18} weight="duotone" />
              </div>
            )}
            <div className="rich-stat-content">
              <span className="rich-stat-value"><AnimatedValue value={stat.value} /></span>
              <span className="rich-stat-label">{stat.label}</span>
            </div>
          </div>
        )
      })}
    </Stagger>
  )
}

export default RichStatsBar
