// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  isPageChange,
  markNavigation,
  navDirection,
  runThemeTransition,
  sharesTransition,
  targetPathname,
  transitionMode,
  withViewTransitions,
} from './viewTransition'
import { magnetOffset } from './magnetic'
import { bandTransform } from '../hooks/useColumnBand'
import { orderChanged } from '../components/motion/primitives'

afterEach(() => {
  delete document.startViewTransition
  delete document.documentElement.dataset.vt
  delete document.documentElement.dataset.dir
})

describe('transitionMode', () => {
  it('travels at full, fades at reduced, never at off or outside Instrument', () => {
    expect(transitionMode('full', 'instrument', true)).toBe('full')
    expect(transitionMode('reduced', 'instrument', true)).toBe('fade')
    expect(transitionMode('off', 'instrument', true)).toBe('none')
    expect(transitionMode('full', 'mission', true)).toBe('none')
    expect(transitionMode('full', 'instrument', false)).toBe('none')
  })
})

describe('page changes and direction', () => {
  const idOf = (p) => (p.startsWith('/dns/zones') ? 'dns-zones' : p)
  it('a list and its detail page are a page change, a query is not', () => {
    expect(isPageChange('/dns/zones', '/dns/zones/example.lan', idOf)).toBe(true)
    expect(isPageChange('/dns/zones/a', '/dns/zones/b', idOf)).toBe(false)
    expect(isPageChange('/', '/dns/zones', idOf)).toBe(true)
    expect(isPageChange('/dns/zones', '/dns/zones/', idOf)).toBe(false)
  })
  it('resolves targets from strings and location objects', () => {
    expect(targetPathname('/dns/zones?view=x', '/')).toBe('/dns/zones')
    expect(targetPathname({ pathname: '/alerts', search: '?a=1' }, '/')).toBe('/alerts')
    expect(targetPathname({ search: '?a=1' }, '/alerts')).toBe('/alerts')
  })
  it('goes back up the path, to the dashboard or by history', () => {
    expect(navDirection('/dns/zones/x', '/dns/zones')).toBe('back')
    expect(navDirection('/alerts', '/')).toBe('back')
    expect(navDirection('/', '/alerts')).toBe('fwd')
    expect(navDirection('/', '/alerts', 'POP')).toBe('back')
  })
})

describe('sharesTransition', () => {
  const t = { isTransitioning: true, currentLocation: { pathname: '/' }, nextLocation: { pathname: '/dns/zones' } }
  it('matches either end of the running transition, other queries ignored', () => {
    expect(sharesTransition(t, '/dns/zones')).toBe(true)
    expect(sharesTransition(t, '/')).toBe(true)
    expect(sharesTransition(t, '/dns/zones?q=a')).toBe(true)
    expect(sharesTransition(t, '/dns/zones/x')).toBe(false)
  })
  it('tells split-horizon views apart and treats _default as no view', () => {
    const d = (search) => ({ isTransitioning: true, currentLocation: { pathname: '/dns/zones', search: '' }, nextLocation: { pathname: '/dns/zones/a.lan', search } })
    expect(sharesTransition(d('?view=internal'), '/dns/zones/a.lan?view=internal')).toBe(true)
    expect(sharesTransition(d('?view=internal'), '/dns/zones/a.lan?view=external')).toBe(false)
    expect(sharesTransition(d('?view=internal'), '/dns/zones/a.lan')).toBe(false)
    expect(sharesTransition(d('?view=_default'), '/dns/zones/a.lan')).toBe(true)
    expect(sharesTransition(d('?view=internal'), '/dns/zones')).toBe(true)
  })
  it('is false when idle or without a router', () => {
    expect(sharesTransition({ ...t, isTransitioning: false }, '/')).toBe(false)
    expect(sharesTransition(null, '/')).toBe(false)
  })
})

describe('withViewTransitions', () => {
  function fake(pathname = '/') {
    const calls = []
    return { calls, state: { location: { pathname } }, navigate: (to, opts) => { calls.push([to, opts]) }, subscribe: () => () => {} }
  }
  const instrument = (level) => () => ({ level, effects: 'instrument' })
  const supported = () => { document.startViewTransition = () => {} }

  it('asks for a view transition on a page change and marks the direction', () => {
    supported()
    const r = withViewTransitions(fake('/dns/zones/x'), { read: instrument('full') })
    r.navigate('/dns/zones')
    expect(r.calls[0][1]).toEqual({ viewTransition: true })
    expect(document.documentElement.dataset.dir).toBe('back')
    expect(document.documentElement.dataset.vt).toBe('nav')
  })
  it('passes through replaces, same-page changes, deltas and level off', () => {
    supported()
    const r = withViewTransitions(fake('/alerts'), { read: instrument('full') })
    r.navigate('/alerts?severity=x')
    r.navigate('/nodes', { replace: true })
    r.navigate(-1)
    expect(r.calls.map((c) => c[1]?.viewTransition)).toEqual([undefined, undefined, undefined])
    const off = withViewTransitions(fake('/'), { read: instrument('off') })
    off.navigate('/nodes')
    expect(off.calls[0][1]).toBeUndefined()
    expect(document.documentElement.dataset.vt).toBeUndefined()
  })
  it('drops the replayed transition of a pop at off or outside Instrument, marks it back otherwise', () => {
    supported()
    const seenOpts = []
    const make = (read) => {
      const r = { ...fake('/'), subscribe: (fn) => { r.emit = fn } }
      withViewTransitions(r, { read })
      r.subscribe((st, o) => seenOpts.push(o))
      return r
    }
    make(instrument('off')).emit({ historyAction: 'POP' }, { viewTransitionOpts: {} })
    make(() => ({ level: 'full', effects: 'mission' })).emit({ historyAction: 'POP' }, { viewTransitionOpts: {} })
    expect(seenOpts).toEqual([{}, {}])
    delete document.documentElement.dataset.dir
    make(instrument('full')).emit({ historyAction: 'POP' }, { viewTransitionOpts: {} })
    expect(seenOpts[2]).toEqual({ viewTransitionOpts: {} })
    expect(document.documentElement.dataset.dir).toBe('back')
    make(instrument('full')).emit({ historyAction: 'PUSH' }, { viewTransitionOpts: {} })
    expect(seenOpts[3]).toEqual({ viewTransitionOpts: {} })
  })
  it('does not start where the browser has no API', () => {
    const r = withViewTransitions(fake('/'), { read: instrument('full') })
    r.navigate('/nodes')
    expect(r.calls[0][1]).toBeUndefined()
  })
})

describe('markNavigation', () => {
  it('sets then clears the root marks', () => {
    vi.useFakeTimers()
    markNavigation('fwd')
    expect(document.documentElement.dataset.vt).toBe('nav')
    vi.advanceTimersByTime(800)
    expect(document.documentElement.dataset.vt).toBeUndefined()
    vi.useRealTimers()
  })
})

describe('runThemeTransition', () => {
  it('cross-fades at full and reduced, applies at once at off', async () => {
    const apply = vi.fn()
    let finish
    document.startViewTransition = (fn) => {
      fn()
      return { finished: new Promise((r) => { finish = r }) }
    }
    expect(runThemeTransition(apply, 'full')).toBe(true)
    expect(document.documentElement.dataset.vt).toBe('theme')
    finish()
    await Promise.resolve()
    await Promise.resolve()
    expect(document.documentElement.dataset.vt).toBeUndefined()
    expect(runThemeTransition(apply, 'reduced')).toBe(true)
    expect(runThemeTransition(apply, 'off')).toBe(false)
    expect(apply).toHaveBeenCalledTimes(3)
  })
  it('applies directly without the API', () => {
    const apply = vi.fn()
    expect(runThemeTransition(apply, 'full')).toBe(false)
    expect(apply).toHaveBeenCalledOnce()
  })
})

describe('magnetOffset', () => {
  const rect = { left: 100, top: 100, width: 80, height: 30 }
  it('leans toward the pointer by at most one pixel', () => {
    expect(magnetOffset(rect, 140, 115)).toEqual({ x: 0, y: 0 })
    expect(magnetOffset(rect, 180, 115).x).toBe(1)
    expect(magnetOffset(rect, 400, -50)).toEqual({ x: 1, y: -1 })
    expect(magnetOffset(rect, 120, 115).x).toBeCloseTo(-0.5)
  })
})

describe('column band and reorders', () => {
  it('places and scales the band over a cell', () => {
    expect(bandTransform({ left: 250, width: 150 }, { left: 50 })).toBe('translateX(200.0px) scaleX(1.500)')
  })
  it('flags only a change of order among shared keys', () => {
    expect(orderChanged(['a', 'b', 'c'], ['c', 'b', 'a'])).toBe(true)
    expect(orderChanged(['a', 'b', 'c'], ['a', 'x', 'b', 'c'])).toBe(false)
    expect(orderChanged(['a', 'b', 'c'], ['a', 'c'])).toBe(false)
    expect(orderChanged(['a'], ['a'])).toBe(false)
    expect(orderChanged([], ['a', 'b'])).toBe(false)
  })
})
