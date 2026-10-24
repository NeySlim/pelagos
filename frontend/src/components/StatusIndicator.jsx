// SPDX-License-Identifier: Apache-2.0
// Dot indicator with an optional label. The pulse is the fx-dot-pulse loop, so the
// motion level and a hidden page gate it like every other animation.
import { StatusDot } from './motion/Decor'

const STATUS_TONES = {
  valid: 'success',
  success: 'success',
  active: 'success',
  online: 'success',
  expiring: 'warning',
  warning: 'warning',
  pending: 'warning',
  expired: 'danger',
  danger: 'danger',
  error: 'danger',
  revoked: 'danger',
  inactive: 'neutral',
  disabled: 'neutral',
  offline: 'neutral',
}

const SIZES = { sm: 8, md: 10, lg: 12 }

export function StatusIndicator({ status, pulse = false, size = 'md', children }) {
  return (
    <div className="inline-flex items-center gap-2">
      <StatusDot tone={STATUS_TONES[status] || 'neutral'} pulse={pulse} size={SIZES[size] || SIZES.md} />
      {children && <span className="text-sm text-text-primary">{children}</span>}
    </div>
  )
}
