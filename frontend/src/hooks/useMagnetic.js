// SPDX-License-Identifier: Apache-2.0
// One delegated listener for every [data-magnetic] button. Full motion, Instrument and a
// fine pointer only; the lean is the `translate` property, which the spring eases.
import { useEffect } from 'react'
import { useMotionLevel } from '../contexts/MotionContext'
import { useTheme } from '../contexts/ThemeContext'
import { magnetOffset } from '../lib/magnetic'

export function useMagnetic() {
  const level = useMotionLevel()
  const { effects } = useTheme()
  useEffect(() => {
    const fine = typeof window.matchMedia === 'function' && window.matchMedia('(pointer: fine)').matches
    if (level !== 'full' || effects !== 'instrument' || !fine) return undefined
    let current = null
    const release = () => {
      if (current) current.style.translate = ''
      current = null
    }
    const move = (e) => {
      const el = e.target instanceof Element ? e.target.closest('[data-magnetic]') : null
      if (el !== current) release()
      if (!el || el.disabled) return
      current = el
      const o = magnetOffset(el.getBoundingClientRect(), e.clientX, e.clientY)
      el.style.translate = `${Number(o.x.toFixed(2))}px ${Number(o.y.toFixed(2))}px`
    }
    document.addEventListener('pointermove', move, { passive: true })
    document.addEventListener('pointerleave', release)
    window.addEventListener('blur', release)
    return () => {
      document.removeEventListener('pointermove', move)
      document.removeEventListener('pointerleave', release)
      window.removeEventListener('blur', release)
      release()
    }
  }, [level, effects])
}
