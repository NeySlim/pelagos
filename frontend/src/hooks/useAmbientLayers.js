// SPDX-License-Identifier: Apache-2.0
// Whether ambient layers exist at all: switched on, Instrument family (no theme provider,
// no layers).
import { useContext } from 'react'
import { useMotion } from '../contexts/MotionContext'
import { ThemeContext } from '../contexts/ThemeContext'

export function useAmbientLayers() {
  const { ambient } = useMotion()
  const theme = useContext(ThemeContext)
  return ambient === 'on' && theme?.effects === 'instrument'
}
