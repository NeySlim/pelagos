// SPDX-License-Identifier: Apache-2.0
// View Transitions for navigation and theme. A page change fades the main region (4 px,
// forward or back); shared elements travel on the spring. Instrument only, never at "off".
// Names are set by the elements themselves while a transition runs (SharedElement), so two
// nodes never hold the same name.

// Upper bound for a marked navigation whose transition never starts (a lazy route can take
// seconds to load); a started transition clears the mark when it finishes, not on a timer.
const VT_CLEAR_MS = 5000

export function supportsViewTransitions() {
  return typeof document !== 'undefined' && typeof document.startViewTransition === 'function'
}

const rootEl = () => (typeof document === 'undefined' ? null : document.documentElement)

// 'full' travels, 'fade' is the 100 ms cross-fade of reduced motion, 'none' swaps at once.
export function transitionMode(level, effects, supported = supportsViewTransitions()) {
  if (!supported || effects !== 'instrument') return 'none'
  if (level === 'full') return 'full'
  if (level === 'reduced') return 'fade'
  return 'none'
}

const trim = (p) => (p.length > 1 ? p.replace(/\/+$/, '') : p)

// Pathname a navigation target resolves to, from the current pathname.
export function targetPathname(to, fromPath) {
  try {
    const raw = typeof to === 'string' ? to : to?.pathname ?? fromPath
    return trim(new URL(raw, `http://x${fromPath}`).pathname)
  } catch {
    return fromPath
  }
}

// A page change is another nav entry, or a list opening its detail page (and back).
export function isPageChange(fromPath, toPath, idOf = (p) => p) {
  const a = trim(fromPath)
  const b = trim(toPath)
  if (a === b) return false
  if (idOf(a) !== idOf(b)) return true
  return a.startsWith(`${b}/`) || b.startsWith(`${a}/`)
}

// 'back' goes up the path (detail to list, any page to the dashboard) or pops history.
export function navDirection(fromPath, toPath, action = 'PUSH') {
  const a = trim(fromPath)
  const b = trim(toPath)
  if (action === 'POP') return 'back'
  if (b === '/' && a !== '/') return 'back'
  return a.startsWith(`${b}/`) ? 'back' : 'fwd'
}

// A page identity: pathname plus the zone view (a split-horizon zone has one page per view).
function pageKey(pathname, search = '') {
  const view = new URLSearchParams(search).get('view')
  return trim(pathname) + (view && view !== '_default' ? `?view=${view}` : '')
}

// True while the router runs a transition from or to the page at `to` (only ?view= counts).
export function sharesTransition(transition, to) {
  if (!transition?.isTransitioning || typeof to !== 'string') return false
  const [path, search = ''] = to.split('#')[0].split('?')
  const key = pageKey(path, search)
  return [transition.currentLocation, transition.nextLocation].some((l) => l && pageKey(l.pathname, l.search) === key)
}

let clearTimer = null
let navTransition = 0

const clearNav = () => {
  const root = rootEl()
  if (root && root.dataset.vt === 'nav') delete root.dataset.vt
}

// Follows the transition the router starts for a marked navigation: the mark must stay until
// it finishes, or the UA root cross-fade plays over the page for the rest of it.
function trackNavTransition() {
  if (typeof document === 'undefined' || document.startViewTransition?.__tracked) return
  const start = document.startViewTransition?.bind(document)
  if (!start) return
  const tracked = (...args) => {
    const transition = start(...args)
    if (rootEl()?.dataset.vt === 'nav') {
      clearTimeout(clearTimer)
      const id = ++navTransition
      const done = () => id === navTransition && clearNav()
      transition.finished.then(done, done)
    }
    return transition
  }
  tracked.__tracked = true
  document.startViewTransition = tracked
}
// Marks the root while a navigation transition runs: CSS names the main region and
// silences the page entry animation; the attribute leaves once the transition is over.
export function markNavigation(direction) {
  const root = rootEl()
  if (!root) return
  root.dataset.dir = direction
  root.dataset.vt = 'nav'
  clearTimeout(clearTimer)
  navTransition++
  clearTimer = setTimeout(clearNav, VT_CLEAR_MS)
}

// Wraps router.navigate so every link and navigate() call changes pages inside a view
// transition. Replaces, deltas and same-page changes (filters, tabs) pass through; a
// history pop keeps its replayed transition only when the level and family allow it.
export function withViewTransitions(router, { idOf, read } = {}) {
  trackNavTransition()
  const original = router.navigate.bind(router)
  const state = read || (() => ({ level: rootEl()?.dataset.motion, effects: rootEl()?.dataset.effects }))
  router.navigate = (to, opts) => {
    if (typeof to === 'number' || opts?.viewTransition !== undefined || opts?.replace) return original(to, opts)
    const { level, effects } = state()
    if (transitionMode(level, effects) === 'none') return original(to, opts)
    const fromPath = router.state.location.pathname
    const toPath = targetPathname(to, fromPath)
    if (!isPageChange(fromPath, toPath, idOf)) return original(to, opts)
    markNavigation(navDirection(fromPath, toPath))
    return original(to, { ...opts, viewTransition: true })
  }
  // History pops reuse the transition RR replays from the push: keep it only when this
  // level and family allow one, and mark it as a way back.
  const subscribe = router.subscribe.bind(router)
  router.subscribe = (fn) =>
    subscribe((routerState, opts) => {
      if (!opts?.viewTransitionOpts || routerState?.historyAction !== 'POP') return fn(routerState, opts)
      const { level, effects } = state()
      if (transitionMode(level, effects) === 'none') {
        const { viewTransitionOpts: _dropped, ...rest } = opts
        return fn(routerState, rest)
      }
      markNavigation('back')
      return fn(routerState, opts)
    })
  return router
}

// Runs `apply` (a synchronous DOM update) inside a root cross-fade; plain call when the
// level does not allow it. Returns whether a transition ran.
export function runThemeTransition(apply, level = rootEl()?.dataset.motion) {
  const root = rootEl()
  if (!root || !supportsViewTransitions() || (level !== 'full' && level !== 'reduced')) {
    apply()
    return false
  }
  root.dataset.vt = 'theme'
  const transition = document.startViewTransition(apply)
  const clear = () => {
    if (root.dataset.vt === 'theme') delete root.dataset.vt
  }
  transition.finished.then(clear, clear)
  return true
}
