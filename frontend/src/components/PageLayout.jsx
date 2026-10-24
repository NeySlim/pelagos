// SPDX-License-Identifier: Apache-2.0
// Page frame used by every screen: UnifiedPageHeader on top, scrollable body below.
import { UnifiedPageHeader } from './ui/UnifiedPageHeader'
import { useMobile } from '../contexts/MobileContext'
import { cn } from '../lib/utils'

export function PageLayout({ icon, title, subtitle, badge, tabs, activeTab, onTabChange, actions, mobileTitle, children, bodyClassName, testId }) {
  const { isMobile } = useMobile()
  return (
    <div className="flex flex-col h-full min-h-0 w-full" data-testid={testId}>
      <UnifiedPageHeader
        icon={icon}
        title={title}
        subtitle={subtitle}
        badge={badge}
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={onTabChange}
        actions={actions}
        isMobile={isMobile}
        mobileTitle={mobileTitle}
      />
      <div className={cn('flex-1 min-h-0 overflow-auto', isMobile ? 'p-3' : 'p-6', bodyClassName)}>{children}</div>
    </div>
  )
}

export default PageLayout
