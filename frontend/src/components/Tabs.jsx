// SPDX-License-Identifier: Apache-2.0
/**
 * Tabs Component - Radix Tabs wrapper. Under Instrument the ink slides between tabs and
 * the panel crossfades; the other families keep their underline.
 */
import * as Tabs from '@radix-ui/react-tabs'
import { useRef, useState } from 'react'
import { cn } from '../lib/utils'
import { TabInk } from './motion/Cursors'

export function TabsComponent({ tabs, defaultTab, className, children: _children }) {
  const [value, setValue] = useState(defaultTab || tabs[0]?.id)
  const listRef = useRef(null)
  return (
    <Tabs.Root value={value} onValueChange={setValue} className={cn("flex flex-col", className)}>
      <Tabs.List ref={listRef} className="ui-tabs relative flex gap-1 border-b border-border">
        {tabs.map(tab => (
          <Tabs.Trigger
            key={tab.id}
            value={tab.id}
            className={cn(
              "ui-tab flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors relative",
              "text-text-secondary hover:text-text-primary",
              "data-[state=active]:text-accent-primary",
              "focus:outline-none"
            )}
          >
            {tab.icon && <span className="flex-shrink-0">{tab.icon}</span>}
            <span>{tab.label}</span>
            <span className="ui-tab-underline absolute bottom-0 left-0 right-0 h-0.5 bg-accent-primary opacity-0 data-[state=active]:opacity-100 transition-opacity" />
          </Tabs.Trigger>
        ))}
        <TabInk container={listRef} activeKey={value} />
      </Tabs.List>

      {tabs.map(tab => (
        <Tabs.Content
          key={tab.id}
          value={tab.id}
          className="ui-tab-panel flex-1 py-4 focus:outline-none"
        >
          {tab.content}
        </Tabs.Content>
      ))}
    </Tabs.Root>
  )
}
