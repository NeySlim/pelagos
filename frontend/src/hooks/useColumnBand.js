// SPDX-License-Identifier: Apache-2.0
// Column band: one band element under a table follows the hovered column (and lights its
// header). One delegated listener, one measure per column change, transform only.
import { useEffect } from 'react'

export const BAND_BASE = 100 // px: the band's layout width, scaled to the column width

// Transform that places a BAND_BASE wide band over a cell, relative to its wrapper.
export function bandTransform(cell, wrap) {
  return `translateX(${(cell.left - wrap.left).toFixed(1)}px) scaleX(${(cell.width / BAND_BASE).toFixed(3)})`
}

export function useColumnBand(wrapRef, bandRef) {
  useEffect(() => {
    const wrap = wrapRef.current
    const band = bandRef.current
    if (!wrap || !band || typeof window.matchMedia !== 'function' || window.matchMedia('(hover: none)').matches) return undefined
    const table = wrap.querySelector('table')
    if (!table) return undefined
    let column = -1
    let lit = null
    const off = () => {
      column = -1
      band.classList.remove('is-on')
      lit?.classList.remove('is-col-hover')
      lit = null
    }
    const move = (e) => {
      const cell = e.target instanceof Element ? e.target.closest('td, th') : null
      if (!cell || cell.colSpan > 1 || !table.contains(cell)) return off()
      if (cell.cellIndex === column) return undefined
      const appearing = column === -1
      column = cell.cellIndex
      // First appearance lands in place; moving between columns glides on the spring.
      band.classList.toggle('is-jump', appearing)
      band.style.transform = bandTransform(cell.getBoundingClientRect(), wrap.getBoundingClientRect())
      band.classList.add('is-on')
      lit?.classList.remove('is-col-hover')
      lit = table.tHead?.rows[0]?.cells[column] || null
      lit?.classList.add('is-col-hover')
      return undefined
    }
    table.addEventListener('pointermove', move, { passive: true })
    table.addEventListener('pointerleave', off)
    return () => {
      table.removeEventListener('pointermove', move)
      table.removeEventListener('pointerleave', off)
      off()
    }
  }, [wrapRef, bandRef])
}
