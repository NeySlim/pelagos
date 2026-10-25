// SPDX-License-Identifier: Apache-2.0
// The one requestAnimationFrame loop shared by every canvas and per-frame animator.
// It runs only while something is registered and the tab is visible, and measures its
// own cost (p95 of script time per frame), readable through loopStats().
import { useEffect, useRef } from 'react'
import { useMotion } from '../contexts/MotionContext'

const COST_WINDOW = 120

const loop = {
  fns: new Map(),
  raf: 0,
  last: 0,
  costs: [],
  frames: 0,
  fps: 0,
  fpsAt: 0,
  totalFrames: 0,
}

const hidden = () => typeof document !== 'undefined' && document.visibilityState === 'hidden'
const raf = typeof window !== 'undefined' && window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : null
const caf = typeof window !== 'undefined' && window.cancelAnimationFrame ? window.cancelAnimationFrame.bind(window) : null

function start() {
  if (loop.raf || !raf || loop.fns.size === 0 || hidden()) return
  loop.raf = raf(tick)
}

function stop() {
  if (loop.raf && caf) caf(loop.raf)
  loop.raf = 0
  loop.last = 0
}

function tick(t) {
  loop.raf = 0
  const t0 = performance.now()
  // A long gap (tab back, debugger) is clamped: animators never jump more than 100 ms.
  const dt = loop.last ? Math.min(100, t - loop.last) : 16
  loop.last = t
  for (const [id, fn] of loop.fns) {
    try {
      fn(t, dt)
    } catch (err) {
      loop.fns.delete(id)
      console.error('animation loop', err)
    }
  }
  loop.costs.push(performance.now() - t0)
  if (loop.costs.length > COST_WINDOW) loop.costs.shift()
  loop.frames += 1
  loop.totalFrames += 1
  if (t - loop.fpsAt >= 1000) {
    loop.fps = loop.frames
    loop.frames = 0
    loop.fpsAt = t
  }
  start()
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (hidden()) stop()
    else start()
  })
}

export function addAnimator(id, fn) {
  loop.fns.set(id, fn)
  start()
}

export function removeAnimator(id) {
  loop.fns.delete(id)
  if (loop.fns.size === 0) stop()
}

// Active animators, frames drawn since load, frames per second and p95 cost per frame (ms).
export function loopStats() {
  const sorted = [...loop.costs].sort((a, b) => a - b)
  const p95 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))] : 0
  return { active: loop.fns.size, running: Boolean(loop.raf), frames: loop.totalFrames, fps: loop.fps, p95 }
}

if (typeof window !== 'undefined' && import.meta.env?.DEV) window.__pelagosLoop = loopStats

// Registers `fn(time, dt)` on the shared loop while `enabled`, at full motion and on a
// visible page. Returns whether it is running; below full the caller redraws on events.
export function useAnimationLoop(fn, { enabled = true } = {}) {
  const { level, hidden: pageIsHidden } = useMotion()
  const ref = useRef(fn)
  useEffect(() => {
    ref.current = fn
  })
  const running = enabled && level === 'full' && !pageIsHidden
  useEffect(() => {
    if (!running) return undefined
    const id = {}
    addAnimator(id, (t, dt) => ref.current(t, dt))
    return () => removeAnimator(id)
  }, [running])
  return running
}
