// SPDX-License-Identifier: Apache-2.0
// DataTable choreography: rows that change order glide (FLIP), a column band follows the pointer.
import { describe, it, expect, afterEach, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { DataTable } from './DataTable'

const columns = [{ key: 'name', label: 'Name' }, { key: 'kind', label: 'Kind' }]
const rows = (names) => names.map((name) => ({ name, kind: 'primary' }))

afterEach(() => vi.restoreAllMocks())

describe('DataTable motion', () => {
  it('glides rows whose order changed and leaves the others', () => {
    // Each row sits at 40 px per position of its text in the current order.
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function rect() {
      const tr = this.closest?.('tbody > tr')
      const i = tr ? [...tr.parentNode.children].indexOf(tr) : 0
      return { top: i * 40, left: 0, width: 100, height: 40, right: 100, bottom: i * 40 + 40 }
    })
    const { rerender } = render(<DataTable columns={columns} rows={rows(['a', 'b', 'c'])} rowKey="name" />)
    // Mark each row by its key; the DOM nodes are kept across the reorder.
    const before = new Map([...document.querySelectorAll('tbody tr')].map((tr) => [tr.textContent.slice(0, 1), tr]))
    rerender(<DataTable columns={columns} rows={rows(['c', 'b', 'a'])} rowKey="name" />)
    expect(before.get('a')).toHaveClass('fx-flip')
    expect(before.get('c')).toHaveClass('fx-flip')
    expect(before.get('b')).not.toHaveClass('fx-flip')
    expect(before.get('a').style.transform).toBe('')
  })

  it('does not glide when rows only come or go', () => {
    const { rerender } = render(<DataTable columns={columns} rows={rows(['a', 'b'])} rowKey="name" />)
    rerender(<DataTable columns={columns} rows={rows(['a', 'x', 'b'])} rowKey="name" />)
    expect(document.querySelector('.fx-flip')).toBeNull()
  })

  it('lights the hovered column and its header', () => {
    vi.stubGlobal('matchMedia', (q) => ({ matches: q === '(pointer: fine)', addEventListener() {}, removeEventListener() {} }))
    render(<DataTable columns={columns} rows={rows(['a'])} rowKey="name" />)
    fireEvent.pointerMove(screen.getAllByRole('cell')[1])
    expect(document.querySelector('.fx-colband')).toHaveClass('is-on')
    expect(screen.getByText('Kind').closest('th')).toHaveClass('is-col-hover')
    fireEvent.pointerLeave(document.querySelector('table'))
    expect(document.querySelector('.fx-colband')).not.toHaveClass('is-on')
    vi.unstubAllGlobals()
  })
})
