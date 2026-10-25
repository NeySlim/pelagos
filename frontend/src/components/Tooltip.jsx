// SPDX-License-Identifier: Apache-2.0
/**
 * Tooltip Component - Radix Tooltip wrapper with configurable delay
 */
import * as Tooltip from '@radix-ui/react-tooltip'
import { Question } from '@phosphor-icons/react'
import { cn } from '../lib/utils'

export function TooltipComponent({ 
  children, 
  content, 
  side = 'top', 
  delayDuration = 400,
  className 
}) {
  return (
    <Tooltip.Provider delayDuration={delayDuration}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          {children}
        </Tooltip.Trigger>
        <Tooltip.Portal>
          <Tooltip.Content
            side={side}
            sideOffset={5}
            className={cn(
              "ui-tooltip bg-bg-tertiary border border-border-op50 px-3 py-2 rounded-lg text-xs text-text-primary shadow-xl z-50 max-w-xs",
              className
            )}
          >
            {content}
            <Tooltip.Arrow className="ui-tooltip-arrow fill-bg-tertiary" />
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  )
}

// Helper icon with tooltip - for field labels
export function HelpTooltip({ content, side = 'top' }) {
  return (
    <TooltipComponent content={content} side={side} delayDuration={300}>
      <button type="button" className="inline-flex text-text-tertiary hover:text-accent-primary transition-colors ml-1">
        <Question size={14} weight="duotone" />
      </button>
    </TooltipComponent>
  )
}
