// SPDX-License-Identifier: Apache-2.0
// Ambient layers sit under the data, below the hairline in contrast. The screen layer is a
// measuring graticule that drifts at the trace paper speed and breathes over 12 s, plus
// faint contours in a corner: two compositor animations, no script. They hold a still
// frame below full motion, on a hidden page, and vanish when ambient is switched off.
import { cn } from '../../lib/utils'

export function AmbientScreen({ className }) {
  return (
    <div className={cn('fx-ambient', className)} aria-hidden="true" data-testid="ambient-screen">
      <div className="fx-ambient-grid fx-loop" />
      <div className="fx-ambient-contour fx-loop" />
    </div>
  )
}
