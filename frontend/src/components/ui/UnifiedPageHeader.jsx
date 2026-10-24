// SPDX-License-Identifier: Apache-2.0
/**
 * UnifiedPageHeader - Global header component for all pages
 * Based on Settings page design (the reference)
 * 
 * Features:
 * - Icon with gradient background
 * - Title + subtitle
 * - Tabs (optional) - Settings style with underline
 * - Filters (optional) - inline on desktop, button on mobile
 * - Actions (optional) - help button, custom actions
 * - Mobile responsive
 */
import { cn } from '../../lib/utils'
import { Question, Funnel } from '@phosphor-icons/react'
import { Badge } from '../Badge'
import { FilterSelect } from './Select'
import { useTranslation } from 'react-i18next'
import { titleCaseClass } from '../../lib/displayCase'
import { IconButton } from '../motion/Layout'

export function UnifiedPageHeader({
  // Title section
  icon: Icon,
  title,
  subtitle,
  badge,
  
  // Tabs (optional)
  tabs,
  activeTab,
  onTabChange,
  
  // Filters (optional)
  filters,
  activeFilters = 0,
  onClearFilters,
  onOpenFilters,
  
  // Actions (optional)
  actions,
  onHelpClick,
  showHelp = false,
  
  // Mobile
  isMobile = false,
  // Detail pages whose title is not the navbar section (a zone page) still show it on mobile.
  mobileTitle = false,
  // True when the title is data (a zone or host name): the display face keeps its case.
  literalTitle,
  
  // Custom className
  className
}) {
  const { t } = useTranslation()
  const hasTabs = tabs && tabs.length > 0
  const hasFilters = filters && filters.length > 0

  return (
    <div className={cn(
      'ui-page-header shrink-0 border-b border-border-op60 bg-bg-secondary shadow-[inset_0_-1px_0_rgba(255,255,255,0.03)]',
      className
    )}>
      {/* Mobile: the title is in the AppShell navbar; page actions stay reachable in a compact row. */}
      {isMobile && mobileTitle && (
        <div className="flex flex-wrap items-center gap-2 px-3 pt-2">
          <h1 className="text-sm font-semibold text-text-primary truncate min-w-0">{title}</h1>
          {badge}
        </div>
      )}
      {isMobile && (actions || hasFilters || (showHelp && onHelpClick)) && (
        <div className="flex flex-wrap items-center justify-end gap-1.5 px-3 py-2" data-testid="page-actions-mobile">
          {hasFilters && (
            <IconButton icon={Funnel} label={t('table.filters')} onClick={onOpenFilters}>
              {activeFilters > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-accent-primary text-white text-2xs flex items-center justify-center">
                  {activeFilters}
                </span>
              )}
            </IconButton>
          )}
          {actions}
          {showHelp && onHelpClick && <IconButton icon={Question} label={t('common.help')} onClick={onHelpClick} />}
        </div>
      )}

      {/* Title row (desktop) */}
      {!isMobile && (
      <div className={cn(
        'flex flex-wrap items-center justify-between gap-x-4 gap-y-2',
        isMobile ? 'px-3 py-2' : 'px-6 py-3'
      )}>
        {/* Left: Icon + Title; at least 16rem wide so actions wrap under it rather than hide it */}
        <div className="flex items-center gap-2 min-w-0 flex-1 basis-64">
          {Icon && (
            <div className={cn(
              "ui-page-icon rounded-lg bg-gradient-to-br from-accent-primary to-accent-primary-op70 flex items-center justify-center shrink-0 shadow-sm",
              isMobile ? "w-7 h-7" : "w-9 h-9"
            )}>
              <Icon size={isMobile ? 14 : 18} weight="bold" className="text-white" />
            </div>
          )}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 min-w-0">
              <h1 className={cn(
                "ui-page-title font-semibold text-text-primary truncate min-w-0 max-w-full",
                titleCaseClass(title, literalTitle),
                isMobile ? "text-sm" : "text-lg"
              )}>
                {title}
              </h1>
              {badge}
            </div>
            {subtitle && !isMobile && (
              <p className="ui-page-subtitle text-sm text-text-secondary truncate">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex flex-wrap items-center justify-end gap-1.5 ml-auto">
          {/* Desktop: Inline filters */}
          {!isMobile && hasFilters && (
            <div className="flex items-center gap-2">
              {filters.slice(0, 3).map((filter) => (
                <FilterSelect
                  key={filter.key}
                  value={filter.value || ''}
                  onChange={filter.onChange}
                  placeholder={filter.placeholder || t('table.allOf', { label: filter.label })}
                  options={filter.options || []}
                  size="sm"
                />
              ))}
              {activeFilters > 0 && (
                <button
                  type="button"
                  onClick={onClearFilters}
                  className="text-xs text-accent-primary hover:underline"
                >
                  {t('table.clearFilters')}
                </button>
              )}
            </div>
          )}
          
          {/* Custom actions */}
          {actions}
          
          {/* Help button */}
          {showHelp && onHelpClick && (
            isMobile ? (
              <IconButton icon={Question} label={t('common.help')} onClick={onHelpClick} />
            ) : (
              <button
                onClick={onHelpClick}
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1.5 rounded-md transition-all",
                  "bg-accent-primary-op10 border border-accent-primary-op30",
                  "text-accent-primary hover:bg-accent-primary-op20",
                  "text-xs font-medium"
                )}
              >
                <Question size={14} weight="bold" />
                <span className="hidden sm:inline">{t('common.help')}</span>
              </button>
            )
          )}
        </div>
      </div>
      )}

      {/* Tabs row (if provided) */}
      {hasTabs && (
        <div className={cn(
          'ui-tabs-row overflow-x-auto scrollbar-hide',
          isMobile ? 'px-3' : 'px-6'
        )}>
          <div className="ui-tabs flex gap-0.5 min-w-max pb-0">
            {tabs.map((tab) => {
              const TabIcon = tab.icon
              const isActive = activeTab === tab.id
              // Only an icon can stand in for the label: an icon-less tab always shows its text.
              const iconOnly = isMobile && !isActive && Boolean(TabIcon)
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => onTabChange?.(tab.id)}
                  aria-label={iconOnly ? tab.label : undefined}
                  title={iconOnly ? tab.label : undefined}
                  className={cn(
                    "ui-tab flex items-center gap-1.5 rounded-t-lg text-sm font-medium transition-all",
                    isActive && "is-active",
                    "border-b-2 -mb-px",
                    isMobile ? "px-2.5 py-1.5" : "px-3 py-2",
                    isActive
                      ? "border-accent-primary text-accent-primary bg-bg-primary"
                      : "border-transparent text-text-secondary hover:text-text-primary hover:bg-tertiary-op50"
                  )}
                >
                  {TabIcon && (
                    <TabIcon size={isMobile ? 14 : 16} weight={isActive ? "fill" : "regular"} />
                  )}
                  <span className={iconOnly ? "hidden" : ""}>
                    {tab.label}
                  </span>
                  {tab.count !== undefined && (
                    <span className={cn(
                      'px-1.5 py-0.5 rounded-full text-2xs font-medium',
                      isActive
                        ? 'bg-accent-primary-op15 text-accent-primary'
                        : 'bg-bg-tertiary text-text-tertiary'
                    )}>
                      {tab.count}
                    </span>
                  )}
                  {tab.badge && (
                    <Badge variant={tab.badge.variant || 'info'} size="sm">
                      {tab.badge.label}
                    </Badge>
                  )}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export default UnifiedPageHeader
