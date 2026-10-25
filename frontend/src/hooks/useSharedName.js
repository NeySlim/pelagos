// SPDX-License-Identifier: Apache-2.0
// The view-transition-name of a shared element while a navigation to or from `to` runs.
// Reads the router's transition context directly, so it is inert outside a data router.
import { useContext } from 'react'
import { UNSAFE_ViewTransitionContext as ViewTransitionContext } from 'react-router-dom'
import { useMotionLevel } from '../contexts/MotionContext'
import { sharesTransition } from '../lib/viewTransition'

export function useSharedName(name, to) {
  const level = useMotionLevel()
  const transition = useContext(ViewTransitionContext)
  return level === 'full' && sharesTransition(transition, to) ? { viewTransitionName: name } : undefined
}
