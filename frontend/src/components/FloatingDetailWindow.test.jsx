// SPDX-License-Identifier: Apache-2.0
// Wide detail windows: per open, centred by the real width change, tiling keeps its width.
import { describe, it, expect, vi } from 'vitest'
import { render, renderHook } from '@testing-library/react'

const captured = []
const wm = { openWindow: vi.fn(), closeWindow: vi.fn(), focusWindow: vi.fn(), updateWindowData: vi.fn() }
vi.mock('../contexts/WindowManagerContext', () => ({ useWindowManager: () => wm, WINDOW_POS_PREFIX: 'pos:' }))
vi.mock('./ui/FloatingWindow', () => ({ FloatingWindow: (props) => { captured.push(props); return null } }))

const { FloatingDetailWindow, useOpenDetail } = await import('./FloatingDetailWindow')

const info = (over = {}) => ({ id: 'host:a', type: 'host', entityId: 'a', data: {}, zIndex: 50, defaultPos: { x: 300, y: 100, w: 520, h: 480 }, ...over })

describe('wide detail windows', () => {
  it('opens 720 px wide, centred by the width change, only for that open', () => {
    const { result } = renderHook(() => useOpenDetail())
    result.current('host', 'a', {}, { wide: true })
    expect(wm.openWindow).toHaveBeenCalledWith('host', 'a', {})
    const first = render(<FloatingDetailWindow windowInfo={info()} />)
    let props = captured.at(-1)
    expect(props.wide).toBe(true)
    expect(props.defaultPos).toMatchObject({ w: 720, x: 200 })
    first.unmount()
    // Reopened without the option: back to the normal width.
    result.current('host', 'a', {})
    render(<FloatingDetailWindow windowInfo={info()} />)
    props = captured.at(-1)
    expect(props.wide).toBe(false)
    expect(props.defaultPos.w).toBe(520)
  })

  it('does not override a tiled width', () => {
    const { result } = renderHook(() => useOpenDetail())
    result.current('host', 'b', {}, { wide: true })
    render(<FloatingDetailWindow windowInfo={info({ id: 'host:b', entityId: 'b', tileKey: 1, defaultPos: { x: 10, y: 10, w: 500, h: 460 } })} />)
    const props = captured.at(-1)
    expect(props.wide).toBe(false)
    expect(props.defaultPos.w).toBe(500)
  })
})
