// SPDX-License-Identifier: Apache-2.0
// Grouped accordion navigation built from the area registry (pages/routes.js),
// filtered by permissions and modules; user menu with theme family, mode and language.
// Groups fold through grid rows; under Instrument a 2 px cursor glides to the active entry.
import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import { House, Gear, SignOut, Check, UserCircle, CaretRight, CaretDown, Globe, Palette, Moon, Sun, Desktop, MagnifyingGlass, CaretDoubleLeft, CaretDoubleRight } from '@phosphor-icons/react'
import { useTheme } from '../contexts/ThemeContext'
import { useAuth } from '../contexts/AuthContext'
import { cn } from '../lib/utils'
import { permitted } from '../lib/access'
import { Logo } from './Logo'
import { WebSocketIndicator } from './WebSocketIndicator'
import { NavCursor } from './motion/Cursors'
import { languages } from '../i18n'
import { persistPreference } from '../stores/preferencesStore'
import { navGroups, allNavItems } from '../pages/routes'
import { searchShortcutLabel, isMac } from '../hooks/useGlobalSearch'

const EXPANDED_KEY = 'pelagos-nav-expanded'
const COLLAPSED_KEY = 'pelagos-nav-collapsed'
const COLLAPSED_WIDTH = 56 // px: icons only

function readCollapsed() {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1'
  } catch {
    return false
  }
}

function itemClass(active, compact) {
  return cn(
    'ui-nav-item flex items-center gap-2 px-2 py-[5px] rounded-md text-[13px] relative',
    compact && 'justify-center !px-0',
    active ? 'is-active nav-item-active bg-accent-primary-op15 text-accent-primary font-medium' : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary',
  )
}

function NavGroup({ group, items, activeId, expanded, onToggle, t, index, fillActive, compact }) {
  if (items.length === 0) return null
  const groupHasActive = items.some((c) => c.id === activeId)
  return (
    <div className="ui-nav-section fx-boot w-full" style={{ '--fx-i': index }}>
      <button
        type="button"
        onClick={onToggle}
        className={cn(
          'ui-nav-group w-full flex items-center gap-2 px-2.5 py-[7px] rounded-md text-[11px] font-semibold tracking-wide uppercase',
          compact && '!px-0 justify-center',
          groupHasActive ? 'has-active text-accent-primary' : 'text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary',
        )}
        aria-expanded={expanded}
        data-group={group.id}
        title={compact ? t(group.labelKey) : undefined}
      >
        <span className={cn('flex-1 truncate', compact ? 'text-center text-[9px]' : 'text-left')}>{t(group.labelKey)}</span>
        {!compact && <CaretDown size={10} weight="bold" className={cn('ui-nav-chevron shrink-0 opacity-50', !expanded && '-rotate-90')} />}
      </button>
      {/* Folds through grid rows; a folded group is inert, so its links leave the tab order. */}
      <div className={cn('ui-nav-fold', expanded && 'is-open')} inert={expanded ? undefined : ''}>
        <div className="ui-nav-items">
          <div className={cn('py-0.5 space-y-px', !compact && 'pl-2')}>
          {items.map((item) => {
            const Icon = item.icon
            const active = activeId === item.id
            const label = t(item.labelKey)
            return (
              <Link key={item.id} to={item.path} title={label} aria-label={compact ? label : undefined} className={itemClass(active, compact)} data-nav={item.id} aria-current={active ? 'page' : undefined}>
                {active && <div className="ui-nav-indicator absolute left-0 w-[3px] h-4 bg-accent-primary rounded-r-full" />}
                {Icon && <Icon size={15} weight={active && fillActive ? 'fill' : 'regular'} className="shrink-0" />}
                {!compact && <span className="truncate">{label}</span>}
              </Link>
            )
          })}
          </div>
        </div>
      </div>
    </div>
  )
}

export function useVisibleNavItems() {
  const { hasPermission, modules } = useAuth()
  return useMemo(
    () =>
      allNavItems.filter((item) => {
        if (!permitted(item, hasPermission)) return false
        if (item.module && !modules?.[item.module]) return false
        return true
      }),
    [hasPermission, modules],
  )
}

export function Sidebar({ activeId, onSearch }) {
  const navigate = useNavigate()
  const { t, i18n } = useTranslation()
  const { themeFamily, setThemeFamily, mode, setMode, themes, effects } = useTheme()
  // Instrument icons keep one weight; the other families fill the active one.
  const fillActive = effects !== 'instrument'
  const { user, logout, node } = useAuth()
  const visibleItems = useVisibleNavItems()
  const navRef = useRef(null)
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const toggleCollapsed = () =>
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSED_KEY, c ? '0' : '1')
      } catch {
        // private browsing
      }
      return !c
    })

  const [expandedGroups, setExpandedGroups] = useState(() => {
    try {
      const stored = localStorage.getItem(EXPANDED_KEY)
      return stored ? JSON.parse(stored) : ['dns', 'dhcp']
    } catch {
      return ['dns', 'dhcp']
    }
  })

  const persistExpanded = (next) => {
    try {
      localStorage.setItem(EXPANDED_KEY, JSON.stringify(next))
    } catch {
      // private browsing
    }
  }

  useEffect(() => {
    const activeItem = visibleItems.find((i) => i.id === activeId)
    if (activeItem && !expandedGroups.includes(activeItem.group)) {
      setExpandedGroups((prev) => {
        const next = [...prev, activeItem.group]
        persistExpanded(next)
        return next
      })
    }
  }, [activeId]) // eslint-disable-line react-hooks/exhaustive-deps

  const toggleGroup = useCallback((groupId) => {
    setExpandedGroups((prev) => {
      const next = prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
      persistExpanded(next)
      return next
    })
  }, [])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const currentLang = i18n.language?.split('-')[0] || 'en'
  const changeLanguage = (code) => {
    i18n.changeLanguage(code)
    persistPreference('language', code)
  }

  const dashboardItem = visibleItems.find((i) => i.id === 'dashboard')
  const accountItem = allNavItems.find((i) => i.id === 'account')
  const modeOptions = [
    { id: 'system', icon: Desktop, labelKey: 'theme.system' },
    { id: 'dark', icon: Moon, labelKey: 'theme.dark' },
    { id: 'light', icon: Sun, labelKey: 'theme.light' },
  ]
  const layoutKey = `${expandedGroups.join(',')}|${visibleItems.length}|${collapsed}`

  return (
    <aside
      className="ui-sidebar w-[200px] h-full border-r border-border bg-bg-secondary flex flex-col py-2.5 overflow-hidden"
      style={collapsed ? { width: COLLAPSED_WIDTH } : undefined}
      id="app-sidebar"
      data-testid="sidebar"
      data-collapsed={collapsed ? 'true' : 'false'}
    >
      <Link to="/" className={cn('ui-brand-row fx-boot flex items-center gap-2.5 px-3.5 mb-1 shrink-0', collapsed && 'justify-center !px-0')} style={{ '--fx-i': 0 }} title={t('nav.dashboard')} aria-label={collapsed ? t('nav.dashboard') : undefined}>
        <Logo variant="icon" withText={false} size="sm" />
        <div className={cn('flex flex-col min-w-0', collapsed && 'hidden')}>
          <span className="ui-brand text-xs font-bold text-text-primary leading-tight">Pelagos</span>
          <span className="ui-brand-node text-3xs text-text-tertiary leading-tight truncate font-mono">{node?.peer?.name || node?.name || t('nav.node')}</span>
        </div>
      </Link>

      <div className="ui-sidebar-rule h-px bg-border mx-3 my-2 shrink-0" />

      {onSearch && (
        <div className={cn('shrink-0 mb-1.5', collapsed ? 'px-2' : 'px-3')}>
          <button
            type="button"
            onClick={onSearch}
            title={collapsed ? t('search.title') : undefined}
            aria-label={t('search.title')}
            aria-keyshortcuts={isMac() ? 'Meta+K /' : 'Control+K /'}
            className={cn('ui-search-trigger w-full flex items-center gap-2 rounded-md border border-border-op50 bg-bg-primary text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary text-xs py-1.5', collapsed ? 'justify-center px-0' : 'px-2')}
            data-testid="global-search-open"
          >
            <MagnifyingGlass size={14} className="shrink-0" aria-hidden="true" />
            {!collapsed && <span className="flex-1 text-left truncate">{t('search.open')}</span>}
            {!collapsed && <kbd className="font-mono text-3xs px-1 rounded border border-border-op50" aria-hidden="true">{searchShortcutLabel()}</kbd>}
          </button>
        </div>
      )}

      <nav ref={navRef} className={cn('ui-nav relative flex-1 overflow-y-auto overflow-x-hidden space-y-0.5', collapsed ? 'px-1' : 'px-2')} aria-label={t('nav.main')}>
        <NavCursor container={navRef} activeKey={activeId} layoutKey={layoutKey} />
        {dashboardItem && (
          <div className="ui-nav-top fx-boot mb-1" style={{ '--fx-i': 1 }}>
            <Link to="/" className={cn(itemClass(activeId === 'dashboard', collapsed), 'px-2.5 py-[6px] w-full')} data-nav="dashboard" title={collapsed ? t('nav.dashboard') : undefined} aria-label={collapsed ? t('nav.dashboard') : undefined} aria-current={activeId === 'dashboard' ? 'page' : undefined}>
              {activeId === 'dashboard' && <div className="ui-nav-indicator absolute left-0 w-[3px] h-4 bg-accent-primary rounded-r-full" />}
              <House size={15} weight={activeId === 'dashboard' && fillActive ? 'fill' : 'regular'} className="shrink-0" />
              {!collapsed && <span>{t('nav.dashboard')}</span>}
            </Link>
          </div>
        )}
        {navGroups.map((group, i) => (
          <NavGroup
            key={group.id}
            group={group}
            items={visibleItems.filter((item) => item.group === group.id)}
            activeId={activeId}
            expanded={expandedGroups.includes(group.id)}
            onToggle={() => toggleGroup(group.id)}
            t={t}
            index={2 + i}
            fillActive={fillActive}
            compact={collapsed}
          />
        ))}
      </nav>

      <div className={cn('shrink-0 px-2 pt-1 flex', collapsed ? 'justify-center' : 'justify-end')}>
        <button
          type="button"
          onClick={toggleCollapsed}
          aria-expanded={!collapsed}
          aria-controls="app-sidebar"
          aria-label={t('nav.sidebar')}
          title={t('nav.sidebar')}
          className="p-1.5 rounded-md text-text-tertiary hover:text-text-secondary hover:bg-bg-tertiary"
          data-testid="nav-collapse"
        >
          {collapsed ? <CaretDoubleRight size={14} /> : <CaretDoubleLeft size={14} />}
        </button>
      </div>

      <div className="ui-user-row fx-boot shrink-0 mt-1 px-2" style={{ '--fx-i': 8 }}>
        <div className="ui-sidebar-rule h-px bg-border mx-1 mb-1.5" />
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button type="button" className={cn('ui-user-button w-full flex items-center gap-2.5 px-2 py-2 rounded-md hover:bg-bg-tertiary transition-colors', collapsed && 'justify-center !px-0')} aria-label={collapsed ? user?.username || t('nav.account') : undefined} data-testid="user-menu">
              <div className="relative shrink-0">
                <div className="ui-avatar w-7 h-7 rounded-full bg-accent-primary-op15 border border-accent-primary-op20 flex items-center justify-center">
                  <UserCircle size={16} weight="bold" className="text-accent-primary" />
                </div>
                <WebSocketIndicator variant="dot" className="absolute -bottom-0.5 -right-0.5" />
              </div>
              {!collapsed && (
                <div className="flex-1 min-w-0 text-left">
                  <div className="text-[13px] font-medium text-text-primary truncate">{user?.username || ''}</div>
                  <div className="text-3xs text-text-tertiary truncate">{(user?.roles || []).join(', ')}</div>
                </div>
              )}
              {!collapsed && <CaretRight size={10} className="text-text-tertiary shrink-0 opacity-60" />}
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="ui-menu min-w-[210px] bg-bg-secondary border border-border rounded-lg shadow-xl p-1 z-50" sideOffset={5} side="right" align="end">
              <div className="px-3 py-2 mb-1">
                <div className="text-sm font-semibold text-text-primary truncate">{user?.username}</div>
                <div className="text-xs text-text-tertiary truncate">{(user?.roles || []).join(', ')}</div>
              </div>
              <DropdownMenu.Separator className="h-px bg-border mb-1" />
              {accountItem && (
                <DropdownMenu.Item onClick={() => navigate(accountItem.path)} className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                  <Gear size={16} />
                  <span>{t('nav.account')}</span>
                </DropdownMenu.Item>
              )}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Label className="ui-menu-label px-3 py-1.5 text-xs text-text-tertiary uppercase tracking-wider flex items-center gap-2">
                <Palette size={12} /> {t('theme.family')}
              </DropdownMenu.Label>
              {themes.map((theme) => (
                <DropdownMenu.Item key={theme.id} onClick={() => setThemeFamily(theme.id)} className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary" data-theme-option={theme.id}>
                  <div className="w-3 h-3 rounded-full border border-border" style={{ background: theme.accent }} />
                  <span className="flex-1 min-w-0">
                    <span className="block">{theme.name}</span>
                    {theme.description && (
                      <span className="block text-3xs text-text-tertiary truncate">
                        {t(`theme.descriptions.${theme.id}`, { defaultValue: theme.description })}
                      </span>
                    )}
                  </span>
                  {themeFamily === theme.id && <Check size={16} weight="bold" className="text-accent-primary" />}
                </DropdownMenu.Item>
              ))}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Label className="ui-menu-label px-3 py-1.5 text-xs text-text-tertiary uppercase tracking-wider">{t('theme.mode')}</DropdownMenu.Label>
              {modeOptions.map((opt) => (
                <DropdownMenu.Item key={opt.id} onClick={() => setMode(opt.id)} className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                  <opt.icon size={16} />
                  <span className="flex-1">{t(opt.labelKey)}</span>
                  {mode === opt.id && <Check size={16} weight="bold" className="text-accent-primary" />}
                </DropdownMenu.Item>
              ))}
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Sub>
                <DropdownMenu.SubTrigger className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary data-[state=open]:bg-bg-tertiary">
                  <Globe size={16} />
                  <span className="flex-1">{languages.find((l) => l.code === currentLang)?.name || 'English'}</span>
                  <CaretRight size={12} className="text-text-tertiary" />
                </DropdownMenu.SubTrigger>
                <DropdownMenu.Portal>
                  <DropdownMenu.SubContent className="ui-menu min-w-[160px] bg-bg-secondary border border-border rounded-lg shadow-lg p-1 z-50">
                    {languages.map((lang) => (
                      <DropdownMenu.Item key={lang.code} onClick={() => changeLanguage(lang.code)} className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-bg-tertiary text-text-primary">
                        <span className="flex-1">{lang.name}</span>
                        {currentLang === lang.code && <Check size={16} weight="bold" className="text-accent-primary" />}
                      </DropdownMenu.Item>
                    ))}
                  </DropdownMenu.SubContent>
                </DropdownMenu.Portal>
              </DropdownMenu.Sub>
              <DropdownMenu.Separator className="h-px bg-border my-1" />
              <DropdownMenu.Item onClick={handleLogout} className="ui-menu-item flex items-center gap-3 px-3 py-2 text-sm rounded-md cursor-pointer outline-none hover:bg-status-danger-op10 text-status-danger" data-testid="logout">
                <SignOut size={16} />
                <span>{t('auth.logout')}</span>
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </aside>
  )
}
