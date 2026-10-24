// SPDX-License-Identifier: Apache-2.0
// Number that counts from its previous value to the new one (hooks/useCountUp). The
// final value reserves the width (no layout shift) and is what assistive technology reads.
import { useCountUp } from '../../hooks/useCountUp'
import { cn } from '../../lib/utils'

const defaultFormat = (n, decimals) =>
  Number(n).toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })

export function CountUp({ value, decimals = 0, duration, format, prefix = '', suffix = '', className, ...props }) {
  const shown = useCountUp(value, { duration })
  const fmt = format || ((n) => defaultFormat(n, decimals))
  const finalText = `${prefix}${fmt(Number(value) || 0)}${suffix}`
  return (
    <span className={cn('fx-count tabular-nums', className)} {...props}>
      <span className="fx-count-ghost" aria-hidden="true">{finalText}</span>
      <span className="fx-count-live" aria-hidden="true">{`${prefix}${fmt(shown)}${suffix}`}</span>
      <span className="sr-only">{finalText}</span>
    </span>
  )
}

export default CountUp
